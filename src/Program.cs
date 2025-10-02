
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Mono.Cecil;
using Mono.Cecil.Cil;

record Finding(string Rule, string Severity, string Message, string Symbol, string? Target, string IlOffset);
record TargetReport(string File, string? Assembly, Dictionary<string,int> Stats, List<Finding> Findings);
record JsonReport(List<TargetReport> Targets);

class Sarif {
    public string version { get; set; } = "2.1.0";
    public List<Run> runs { get; set; } = new();
    public class Run {
        public Tool tool { get; set; } = new();
        public List<Result> results { get; set; } = new();
        public List<Artifact> artifacts { get; set; } = new();
    }
    public class Tool { public Driver driver { get; set; } = new(); }
    public class Driver { public string name { get; set; } = "clr-audit"; public List<Rule> rules { get; set; } = new(); }
    public class Rule { public string id { get; set; } = ""; public string name { get; set; } = ""; public string shortDescription { get; set; } = ""; public string helpUri { get; set; } = ""; }
    public class Result {
        public string ruleId { get; set; } = "";
        public string level { get; set; } = "warning";
        public Message message { get; set; } = new();
        public List<Location> locations { get; set; } = new();
    }
    public class Message { public string text { get; set; } = ""; }
    public class Location { public PhysicalLocation physicalLocation { get; set; } = new(); public List<LogicalLocation>? logicalLocations { get; set; } }
    public class LogicalLocation { public string fullyQualifiedName { get; set; } = ""; }
    public class PhysicalLocation { public ArtifactLocation artifactLocation { get; set; } = new(); public Region? region { get; set; } }
    public class ArtifactLocation { public string uri { get; set; } = ""; }
    public class Region { public int? startLine { get; set; } }
    public class Artifact { public string location { get; set; } = ""; }
}

class App {
    static int Main(string[] args) {
        if (args.Length < 2 || args[0] != "audit") {
            Console.Error.WriteLine("usage: clr-audit audit <file_or_dir> [more ...] [-r] [--json-out f] [--sarif-out f]");
            return 1;
        }
        bool recursive = args.Contains("-r");
        string? jsonOut = null, sarifOut = null;
        for (int i=0;i<args.Length;i++) {
            if (args[i] == "--json-out" && i+1<args.Length) jsonOut = args[i+1];
            if (args[i] == "--sarif-out" && i+1<args.Length) sarifOut = args[i+1];
        }
        var targets = args.Skip(1).Where(a => !a.StartsWith("-")).ToList();
        var files = new List<string>();
        foreach (var t in targets) {
            if (File.Exists(t)) files.Add(t);
            else if (Directory.Exists(t)) {
                var opt = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
                files.AddRange(Directory.GetFiles(t, "*.dll", opt));
                files.AddRange(Directory.GetFiles(t, "*.exe", opt));
            }
        }
        files = files.Distinct().OrderBy(x=>x).ToList();
        var reports = new List<TargetReport>();
        foreach (var f in files) {
            try { reports.Add(Scan(f)); }
            catch (Exception ex) {
                reports.Add(new TargetReport(f, null, new(), new(){ new Finding("ERROR","LOW", ex.Message, "", null, "0x0") }));
            }
        }
        var doc = new JsonReport(reports);
        var jsonOpts = new JsonSerializerOptions{ WriteIndented = true };
        var outStr = JsonSerializer.Serialize(doc, jsonOpts);
        if (jsonOut != null) File.WriteAllText(jsonOut, outStr); else Console.WriteLine(outStr);

        if (sarifOut != null) File.WriteAllText(sarifOut, ToSarif(reports));
        return 0;
    }

    static TargetReport Scan(string file) {
        var findings = new List<Finding>();
        var stats = new Dictionary<string,int>();
        void mark(string key){ stats[key] = stats.TryGetValue(key, out var v) ? v+1 : 1; }

        var resolver = new DefaultAssemblyResolver();
        resolver.AddSearchDirectory(Path.GetDirectoryName(Path.GetFullPath(file))!);
        var rp = new ReaderParameters{ AssemblyResolver = resolver, ReadSymbols = false, ReadWrite = false, InMemory = true };
        using var mod = ModuleDefinition.ReadModule(file, rp);
        string asmName = mod.Assembly?.Name?.Name ?? Path.GetFileName(file);

        foreach (var type in mod.Types) {
            foreach (var m in type.Methods) {
                if (m == null) continue;
                if (m.IsPInvokeImpl) {
                    var dll = m.PInvokeInfo?.Module?.Name ?? "unknown";
                    var msg = $"P/Invoke {dll}!{m.Name}";
                    findings.Add(new Finding("R_PINVOKE","MED", msg, $"{type.FullName}::{m.Name}", dll, "0x0"));
                    mark("pinvoke");
                }
                if (!m.HasBody) continue;
                var il = m.Body.Instructions;
                foreach (var ins in il) {
                    if (ins.OpCode == OpCodes.Calli) {
                        findings.Add(new Finding("R_CALLI","MED", "calli used", $"{type.FullName}::{m.Name}", null, Offset(ins)));
                        mark("calli");
                    }
                    if (ins.OpCode.Code is Code.Call or Code.Callvirt or Code.Newobj) {
                        if (ins.Operand is not MethodReference mr) continue;
                        var tn = mr.DeclaringType?.FullName ?? "";
                        var mn = mr.Name;
                        var sig = mr.FullName;
                        // a) Assembly.Load / LoadFrom / LoadFile
                        if (tn == "System.Reflection.Assembly" && (mn.StartsWith("Load") || mn == "LoadFrom" || mn == "LoadFile")) {
                            var sev = sig.Contains("System.Byte[]") ? "HIGH" : "MED";
                            findings.Add(new Finding("R_ASM_LOAD", sev, $"Assembly load: {sig}", $"{type.FullName}::{m.Name}", sig, Offset(ins)));
                            mark("asm_load");
                        }
                        // b) Process.Start
                        if (tn == "System.Diagnostics.Process" && mn == "Start") {
                            findings.Add(new Finding("R_PROC_START","MED", $"Process.Start: {sig}", $"{type.FullName}::{m.Name}", sig, Offset(ins)));
                            mark("proc_start");
                        }
                        // c) BinaryFormatter
                        if (tn == "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter" &&
                           (mn == ".ctor" || mn == "Serialize" || mn == "Deserialize")) {
                            findings.Add(new Finding("R_BINFORMATTER","HIGH", $"BinaryFormatter: {sig}", $"{type.FullName}::{m.Name}", sig, Offset(ins)));
                            mark("binfmt");
                        }
                        // d) Reflection.Emit / DynamicMethod / DispatchProxy
                        if (tn.StartsWith("System.Reflection.Emit") || tn == "System.Reflection.DispatchProxy" || tn == "System.Reflection.Emit.DynamicMethod") {
                            findings.Add(new Finding("R_REF_EMIT","MED", $"Emit/proxy: {sig}", $"{type.FullName}::{m.Name}", sig, Offset(ins)));
                            mark("emit");
                        }
                    }
                }
            }
        }
        return new TargetReport(file, asmName, stats, findings);
    }

    static string Offset(Instruction ins) => "0x" + ins.Offset.ToString("X");

    static string ToSarif(List<TargetReport> reps) {
        var sarif = new Sarif();
        var run = new Sarif.Run();
        run.tool.driver.rules = new List<Sarif.Rule> {
            new(){ id="R_ASM_LOAD", name="AssemblyLoad", shortDescription="Assembly.Load/From/File"},
            new(){ id="R_PINVOKE", name="PInvoke", shortDescription="DllImport/PInvoke"},
            new(){ id="R_PROC_START", name="ProcessStart", shortDescription="System.Diagnostics.Process.Start"},
            new(){ id="R_BINFORMATTER", name="BinaryFormatter", shortDescription="BinaryFormatter usage"},
            new(){ id="R_REF_EMIT", name="ReflectionEmit", shortDescription="Reflection.Emit / proxies"},
            new(){ id="R_CALLI", name="Calli", shortDescription="IL calli"}
        };
        foreach (var r in reps) {
            foreach (var f in r.Findings) {
                run.results.Add(new Sarif.Result {
                    ruleId = f.Rule,
                    level = f.Severity switch { "HIGH" => "error", "MED" => "warning", _ => "note" },
                    message = new Sarif.Message{ text = $"{f.Message} @ {f.Symbol}" },
                    locations = new List<Sarif.Location> {
                        new Sarif.Location {
                            physicalLocation = new Sarif.PhysicalLocation{ artifactLocation = new Sarif.ArtifactLocation{ uri = r.File } },
                            logicalLocations = new List<Sarif.LogicalLocation>{ new(){ fullyQualifiedName = f.Symbol } }
                        }
                    }
                });
            }
        }
        sarif.runs.Add(run);
        return System.Text.Json.JsonSerializer.Serialize(sarif, new JsonSerializerOptions{ WriteIndented = true });
    }
}
