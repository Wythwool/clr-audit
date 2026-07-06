using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Mono.Cecil;
using Mono.Cecil.Cil;

const string ToolName = "clr-audit";
var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.0.0";

var cli = CliOptions.Parse(args);
if (cli.ShowHelp)
{
    Usage(Console.Out);
    return 0;
}
if (cli.ShowVersion)
{
    Console.WriteLine(version);
    return 0;
}
if (cli.Error is not null)
{
    Console.Error.WriteLine(cli.Error);
    Usage(Console.Error);
    return 1;
}

var files = TargetDiscovery.FindAssemblies(cli.Targets, cli.Recursive);
if (files.Count == 0)
{
    Console.Error.WriteLine("no .dll or .exe inputs found");
    return 1;
}

var scanner = new AssemblyScanner();
var targets = new List<TargetReport>();
foreach (var file in files)
{
    targets.Add(scanner.Scan(file));
}

var report = ReportBuilder.Build(ToolName, version, targets);
var jsonOptions = JsonSettings.Create();
var json = JsonSerializer.Serialize(report, jsonOptions);

if (cli.JsonOut is null)
{
    Console.WriteLine(json);
}
else
{
    WriteText(cli.JsonOut, json);
}

if (cli.SarifOut is not null)
{
    WriteText(cli.SarifOut, SarifWriter.Write(report));
}
if (cli.CsvOut is not null)
{
    WriteText(cli.CsvOut, CsvWriter.Write(report));
}
if (cli.MarkdownOut is not null)
{
    WriteText(cli.MarkdownOut, MarkdownWriter.Write(report));
}

return cli.FailOn == SeverityThreshold.None || !report.Summary.Meets(cli.FailOn) ? 0 : 3;

static void Usage(TextWriter writer)
{
    writer.WriteLine("usage: clr-audit audit <file_or_dir> [more ...] [-r|--recursive]");
    writer.WriteLine("       [--json-out file] [--sarif-out file] [--csv-out file] [--md-out file]");
    writer.WriteLine("       [--fail-on none|low|medium|high]");
}

static void WriteText(string path, string text)
{
    var dir = Path.GetDirectoryName(Path.GetFullPath(path));
    if (!string.IsNullOrWhiteSpace(dir))
    {
        Directory.CreateDirectory(dir);
    }
    File.WriteAllText(path, text, Encoding.UTF8);
}

enum SeverityThreshold
{
    None,
    Low,
    Medium,
    High,
}

sealed record CliOptions(
    bool ShowHelp,
    bool ShowVersion,
    bool Recursive,
    IReadOnlyList<string> Targets,
    string? JsonOut,
    string? SarifOut,
    string? CsvOut,
    string? MarkdownOut,
    SeverityThreshold FailOn,
    string? Error)
{
    public static CliOptions Parse(string[] args)
    {
        if (args.Length == 0)
        {
            return new CliOptions(false, false, false, Array.Empty<string>(), null, null, null, null,
                SeverityThreshold.None, "missing command");
        }

        if (args[0] is "-h" or "--help")
        {
            return Help();
        }
        if (args[0] is "--version" or "version")
        {
            return Version();
        }
        if (!string.Equals(args[0], "audit", StringComparison.Ordinal))
        {
            return Invalid($"unknown command: {args[0]}");
        }

        var recursive = false;
        string? jsonOut = null;
        string? sarifOut = null;
        string? csvOut = null;
        string? markdownOut = null;
        var failOn = SeverityThreshold.None;
        var targets = new List<string>();

        for (var i = 1; i < args.Length; i++)
        {
            var arg = args[i];
            switch (arg)
            {
                case "-h":
                case "--help":
                    return Help();
                case "--version":
                    return Version();
                case "-r":
                case "--recursive":
                    recursive = true;
                    break;
                case "--json-out":
                    if (!TakeValue(args, ref i, out jsonOut, out var jsonError))
                    {
                        return Invalid(jsonError);
                    }
                    break;
                case "--sarif-out":
                    if (!TakeValue(args, ref i, out sarifOut, out var sarifError))
                    {
                        return Invalid(sarifError);
                    }
                    break;
                case "--csv-out":
                    if (!TakeValue(args, ref i, out csvOut, out var csvError))
                    {
                        return Invalid(csvError);
                    }
                    break;
                case "--md-out":
                case "--markdown-out":
                    if (!TakeValue(args, ref i, out markdownOut, out var mdError))
                    {
                        return Invalid(mdError);
                    }
                    break;
                case "--fail-on":
                    if (!TakeValue(args, ref i, out var rawFailOn, out var failError))
                    {
                        return Invalid(failError);
                    }
                    if (!ParseThreshold(rawFailOn, out failOn))
                    {
                        return Invalid("invalid --fail-on value; use none, low, medium, or high");
                    }
                    break;
                default:
                    if (arg.StartsWith("-", StringComparison.Ordinal))
                    {
                        return Invalid($"unknown option: {arg}");
                    }
                    targets.Add(arg);
                    break;
            }
        }

        if (targets.Count == 0)
        {
            return Invalid("missing file or directory target");
        }

        return new CliOptions(false, false, recursive, targets, jsonOut, sarifOut, csvOut,
            markdownOut, failOn, null);
    }

    private static CliOptions Help() => new(true, false, false, Array.Empty<string>(), null, null, null,
        null, SeverityThreshold.None, null);

    private static CliOptions Version() => new(false, true, false, Array.Empty<string>(), null, null,
        null, null, SeverityThreshold.None, null);

    private static CliOptions Invalid(string message) => new(false, false, false, Array.Empty<string>(),
        null, null, null, null, SeverityThreshold.None, message);

    private static bool TakeValue(string[] args, ref int index, [NotNullWhen(true)] out string? value,
        [NotNullWhen(false)] out string? error)
    {
        if (index + 1 >= args.Length || args[index + 1].StartsWith("-", StringComparison.Ordinal))
        {
            value = null;
            error = $"missing value for {args[index]}";
            return false;
        }
        value = args[++index];
        error = null;
        return true;
    }

    private static bool ParseThreshold(string value, out SeverityThreshold threshold)
    {
        threshold = value.ToLowerInvariant() switch
        {
            "none" => SeverityThreshold.None,
            "low" => SeverityThreshold.Low,
            "medium" or "med" => SeverityThreshold.Medium,
            "high" => SeverityThreshold.High,
            _ => SeverityThreshold.None,
        };
        return value.Equals("none", StringComparison.OrdinalIgnoreCase)
               || value.Equals("low", StringComparison.OrdinalIgnoreCase)
               || value.Equals("medium", StringComparison.OrdinalIgnoreCase)
               || value.Equals("med", StringComparison.OrdinalIgnoreCase)
               || value.Equals("high", StringComparison.OrdinalIgnoreCase);
    }
}

static class TargetDiscovery
{
    public static IReadOnlyList<string> FindAssemblies(IReadOnlyList<string> targets, bool recursive)
    {
        var files = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var target in targets)
        {
            if (File.Exists(target))
            {
                if (IsAssemblyCandidate(target))
                {
                    files.Add(Path.GetFullPath(target));
                }
                continue;
            }

            if (!Directory.Exists(target))
            {
                continue;
            }

            var option = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
            foreach (var file in Directory.EnumerateFiles(target, "*.*", option)
                         .Where(IsAssemblyCandidate))
            {
                files.Add(Path.GetFullPath(file));
            }
        }
        return files.ToList();
    }

    private static bool IsAssemblyCandidate(string path)
    {
        var ext = Path.GetExtension(path);
        return ext.Equals(".dll", StringComparison.OrdinalIgnoreCase)
               || ext.Equals(".exe", StringComparison.OrdinalIgnoreCase);
    }
}

sealed class AssemblyScanner
{
    public TargetReport Scan(string file)
    {
        var findings = new List<Finding>();
        var stats = new SortedDictionary<string, int>(StringComparer.Ordinal);

        try
        {
            var resolver = new DefaultAssemblyResolver();
            var dir = Path.GetDirectoryName(Path.GetFullPath(file));
            if (!string.IsNullOrWhiteSpace(dir))
            {
                resolver.AddSearchDirectory(dir);
            }

            var reader = new ReaderParameters
            {
                AssemblyResolver = resolver,
                ReadSymbols = false,
                ReadWrite = false,
                InMemory = true,
            };
            using var module = ModuleDefinition.ReadModule(file, reader);
            var assemblyName = module.Assembly?.Name?.Name ?? Path.GetFileNameWithoutExtension(file);

            foreach (var resource in module.Resources)
            {
                ScanResource(file, assemblyName, resource, findings, stats);
            }

            foreach (var type in AllTypes(module.Types))
            {
                foreach (var method in type.Methods)
                {
                    ScanMethod(file, assemblyName, type, method, findings, stats);
                }
            }

            return new TargetReport(file, assemblyName, true, null, stats, findings);
        }
        catch (Exception ex) when (ex is BadImageFormatException or IOException or UnauthorizedAccessException
                                  or AssemblyResolutionException)
        {
            findings.Add(new Finding("R_SCAN_ERROR", "low", ex.Message, file, null, null, null, null, "0x0"));
            Bump(stats, "scan_error");
            return new TargetReport(file, null, false, ex.Message, stats, findings);
        }
    }

    private static void ScanMethod(string file, string assemblyName, TypeDefinition type, MethodDefinition method,
        List<Finding> findings, SortedDictionary<string, int> stats)
    {
        var symbol = $"{type.FullName}::{method.Name}";
        if (method.IsPInvokeImpl)
        {
            var dll = method.PInvokeInfo?.Module?.Name ?? "unknown";
            Add(findings, stats, "R_PINVOKE", "medium", $"P/Invoke import: {dll}!{method.Name}", file,
                assemblyName, type.FullName, method.FullName, dll, "0x0", "pinvoke");
        }

        if (!method.HasBody)
        {
            return;
        }

        foreach (var instruction in method.Body.Instructions)
        {
            if (instruction.OpCode.Code == Code.Calli)
            {
                Add(findings, stats, "R_CALLI", "medium", "IL calli instruction", file, assemblyName,
                    type.FullName, method.FullName, null, Offset(instruction), "calli");
                continue;
            }

            if (instruction.OpCode.Code == Code.Ldstr && instruction.Operand is string text)
            {
                ScanString(file, assemblyName, type, method, instruction, text, findings, stats);
                continue;
            }

            if (instruction.OpCode.Code is not (Code.Call or Code.Callvirt or Code.Newobj))
            {
                continue;
            }

            if (instruction.Operand is MethodReference methodRef)
            {
                ScanCall(file, assemblyName, type, method, instruction, methodRef, findings, stats);
            }
        }

        _ = symbol;
    }

    private static void ScanCall(string file, string assemblyName, TypeDefinition type, MethodDefinition method,
        Instruction instruction, MethodReference methodRef, List<Finding> findings,
        SortedDictionary<string, int> stats)
    {
        var owner = methodRef.DeclaringType?.FullName ?? "";
        var name = methodRef.Name;
        var target = methodRef.FullName;

        if (owner == "System.Reflection.Assembly" && name.StartsWith("Load", StringComparison.Ordinal))
        {
            var hasByteArray = methodRef.Parameters.Any(p => p.ParameterType.FullName == "System.Byte[]");
            Add(findings, stats, "R_ASSEMBLY_LOAD", hasByteArray ? "high" : "medium",
                $"Dynamic assembly load: {target}", file, assemblyName, type.FullName, method.FullName,
                target, Offset(instruction), "assembly_load");
        }

        if (owner == "System.Diagnostics.Process" && name == "Start")
        {
            Add(findings, stats, "R_PROCESS_START", "medium", $"Process start: {target}", file,
                assemblyName, type.FullName, method.FullName, target, Offset(instruction), "process_start");
        }

        if (owner == "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter"
            && name is ".ctor" or "Serialize" or "Deserialize")
        {
            Add(findings, stats, "R_BINARY_FORMATTER", "high", $"BinaryFormatter usage: {target}", file,
                assemblyName, type.FullName, method.FullName, target, Offset(instruction), "binary_formatter");
        }

        if (owner.StartsWith("System.Reflection.Emit", StringComparison.Ordinal)
            || owner == "System.Reflection.DispatchProxy")
        {
            Add(findings, stats, "R_REFLECTION_EMIT", "medium", $"Reflection emit/proxy: {target}", file,
                assemblyName, type.FullName, method.FullName, target, Offset(instruction), "reflection_emit");
        }

        if (owner == "System.Runtime.InteropServices.Marshal"
            && name is "GetDelegateForFunctionPointer" or "PtrToStructure")
        {
            Add(findings, stats, "R_MARSHAL_NATIVE", "medium", $"Native marshaling: {target}", file,
                assemblyName, type.FullName, method.FullName, target, Offset(instruction), "marshal_native");
        }

        if (owner == "System.Runtime.InteropServices.NativeLibrary" && name.StartsWith("Load", StringComparison.Ordinal))
        {
            Add(findings, stats, "R_NATIVE_LIBRARY_LOAD", "medium", $"Native library load: {target}", file,
                assemblyName, type.FullName, method.FullName, target, Offset(instruction), "native_load");
        }

        if ((owner == "System.Net.WebClient" && name.StartsWith("Download", StringComparison.Ordinal))
            || (owner == "System.Net.Http.HttpClient" && name.StartsWith("Get", StringComparison.Ordinal)))
        {
            Add(findings, stats, "R_NETWORK_FETCH", "medium", $"Network fetch API: {target}", file,
                assemblyName, type.FullName, method.FullName, target, Offset(instruction), "network_fetch");
        }
    }

    private static void ScanString(string file, string assemblyName, TypeDefinition type, MethodDefinition method,
        Instruction instruction, string text, List<Finding> findings, SortedDictionary<string, int> stats)
    {
        if (LooksLikeBase64(text))
        {
            Add(findings, stats, "R_ENCODED_STRING", "low", "Long base64-like string literal", file,
                assemblyName, type.FullName, method.FullName, TrimForReport(text), Offset(instruction),
                "encoded_string");
        }
        if (text.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || text.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            Add(findings, stats, "R_URL_LITERAL", "low", "URL string literal", file, assemblyName,
                type.FullName, method.FullName, TrimForReport(text), Offset(instruction), "url_literal");
        }
    }

    private static void ScanResource(string file, string assemblyName, Resource resource,
        List<Finding> findings, SortedDictionary<string, int> stats)
    {
        if (resource is not EmbeddedResource embedded)
        {
            return;
        }

        var name = embedded.Name;
        var lower = name.ToLowerInvariant();
        if (lower.EndsWith(".dll", StringComparison.Ordinal) || lower.EndsWith(".exe", StringComparison.Ordinal))
        {
            Add(findings, stats, "R_EXECUTABLE_RESOURCE", "medium", $"Executable-looking resource: {name}",
                file, assemblyName, null, null, name, "0x0", "executable_resource");
        }
    }

    private static IEnumerable<TypeDefinition> AllTypes(IEnumerable<TypeDefinition> roots)
    {
        foreach (var type in roots)
        {
            yield return type;
            foreach (var nested in AllTypes(type.NestedTypes))
            {
                yield return nested;
            }
        }
    }

    private static bool LooksLikeBase64(string value)
    {
        if (value.Length < 80 || value.Length % 4 != 0)
        {
            return false;
        }

        var good = value.Count(c => char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '=');
        return (double)good / value.Length > 0.95;
    }

    private static string TrimForReport(string value)
    {
        return value.Length <= 120 ? value : string.Concat(value.AsSpan(0, 117), "...");
    }

    private static string Offset(Instruction instruction)
    {
        return "0x" + instruction.Offset.ToString("X4", CultureInfo.InvariantCulture);
    }

    private static void Add(List<Finding> findings, SortedDictionary<string, int> stats, string ruleId,
        string severity, string message, string file, string assemblyName, string? type, string? method,
        string? target, string ilOffset, string statKey)
    {
        findings.Add(new Finding(ruleId, severity, message, file, assemblyName, type, method, target, ilOffset));
        Bump(stats, statKey);
    }

    private static void Bump(SortedDictionary<string, int> stats, string key)
    {
        stats[key] = stats.TryGetValue(key, out var value) ? value + 1 : 1;
    }
}

sealed record ToolMetadata(string Name, string Version, string GeneratedAt);

sealed record Summary(int Files, int Scanned, int Errors, int Findings, int High, int Medium, int Low)
{
    public bool Meets(SeverityThreshold threshold)
    {
        return threshold switch
        {
            SeverityThreshold.High => High > 0,
            SeverityThreshold.Medium => High + Medium > 0,
            SeverityThreshold.Low => High + Medium + Low > 0,
            _ => false,
        };
    }
}

sealed record Finding(
    string RuleId,
    string Severity,
    string Message,
    string File,
    string? Assembly,
    string? Type,
    string? Method,
    string? Target,
    string IlOffset);

sealed record TargetReport(
    string File,
    string? Assembly,
    bool Scanned,
    string? Error,
    IReadOnlyDictionary<string, int> Stats,
    IReadOnlyList<Finding> Findings);

sealed record JsonReport(ToolMetadata Tool, Summary Summary, IReadOnlyList<TargetReport> Targets);

static class ReportBuilder
{
    public static JsonReport Build(string toolName, string version, IReadOnlyList<TargetReport> targets)
    {
        var findings = targets.SelectMany(t => t.Findings).ToList();
        var summary = new Summary(
            targets.Count,
            targets.Count(t => t.Scanned),
            targets.Count(t => !t.Scanned),
            findings.Count,
            findings.Count(f => f.Severity == "high"),
            findings.Count(f => f.Severity == "medium"),
            findings.Count(f => f.Severity == "low"));

        var metadata = new ToolMetadata(toolName, version, DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
        return new JsonReport(metadata, summary, targets);
    }
}

static class JsonSettings
{
    public static JsonSerializerOptions Create()
    {
        return new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };
    }
}

static class CsvWriter
{
    public static string Write(JsonReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine("file,assembly,rule_id,severity,type,method,il_offset,target,message");
        foreach (var finding in report.Targets.SelectMany(t => t.Findings))
        {
            sb.AppendJoin(',', new[]
            {
                Escape(finding.File),
                Escape(finding.Assembly),
                Escape(finding.RuleId),
                Escape(finding.Severity),
                Escape(finding.Type),
                Escape(finding.Method),
                Escape(finding.IlOffset),
                Escape(finding.Target),
                Escape(finding.Message),
            });
            sb.AppendLine();
        }
        return sb.ToString();
    }

    private static string Escape(string? value)
    {
        value ??= "";
        return value.Any(c => c is ',' or '"' or '\n' or '\r')
            ? "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\""
            : value;
    }
}

static class MarkdownWriter
{
    public static string Write(JsonReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# clr-audit report");
        sb.AppendLine();
        sb.AppendLine($"Generated: `{report.Tool.GeneratedAt}`");
        sb.AppendLine();
        sb.AppendLine("| Files | Scanned | Errors | Findings | High | Medium | Low |");
        sb.AppendLine("|---:|---:|---:|---:|---:|---:|---:|");
        sb.AppendLine($"| {report.Summary.Files} | {report.Summary.Scanned} | {report.Summary.Errors} | {report.Summary.Findings} | {report.Summary.High} | {report.Summary.Medium} | {report.Summary.Low} |");
        sb.AppendLine();
        sb.AppendLine("| Rule | Severity | Assembly | Symbol | Offset | Target |");
        sb.AppendLine("|---|---|---|---|---|---|");
        foreach (var finding in report.Targets.SelectMany(t => t.Findings))
        {
            var symbol = finding.Method ?? finding.Type ?? "";
            sb.AppendLine($"| `{finding.RuleId}` | {finding.Severity} | `{finding.Assembly ?? ""}` | `{EscapeCell(symbol)}` | `{finding.IlOffset}` | `{EscapeCell(finding.Target ?? "")}` |");
        }
        return sb.ToString();
    }

    private static string EscapeCell(string value) => value.Replace("|", "\\|", StringComparison.Ordinal);
}

static class SarifWriter
{
    private static readonly IReadOnlyDictionary<string, (string Name, string Description)> Rules =
        new SortedDictionary<string, (string, string)>(StringComparer.Ordinal)
        {
            ["R_ASSEMBLY_LOAD"] = ("AssemblyLoad", "Dynamic Assembly.Load, LoadFrom, or LoadFile usage"),
            ["R_BINARY_FORMATTER"] = ("BinaryFormatter", "BinaryFormatter construction or serialization usage"),
            ["R_CALLI"] = ("Calli", "IL calli instruction"),
            ["R_ENCODED_STRING"] = ("EncodedString", "Long base64-like string literal"),
            ["R_EXECUTABLE_RESOURCE"] = ("ExecutableResource", "Embedded resource with executable-looking name"),
            ["R_MARSHAL_NATIVE"] = ("MarshalNative", "Native pointer marshaling API"),
            ["R_NATIVE_LIBRARY_LOAD"] = ("NativeLibraryLoad", "NativeLibrary.Load usage"),
            ["R_NETWORK_FETCH"] = ("NetworkFetch", "Network fetch API usage"),
            ["R_PINVOKE"] = ("PInvoke", "P/Invoke import"),
            ["R_PROCESS_START"] = ("ProcessStart", "Process.Start usage"),
            ["R_REFLECTION_EMIT"] = ("ReflectionEmit", "Reflection.Emit or dynamic method usage"),
            ["R_SCAN_ERROR"] = ("ScanError", "Input could not be scanned"),
            ["R_URL_LITERAL"] = ("UrlLiteral", "URL string literal"),
        };

    public static string Write(JsonReport report)
    {
        var sarif = new SarifLog
        {
            Runs =
            [
                new SarifRun
                {
                    Tool = new SarifTool
                    {
                        Driver = new SarifDriver
                        {
                            Name = report.Tool.Name,
                            Version = report.Tool.Version,
                            Rules = Rules.Select(r => new SarifRule
                            {
                                Id = r.Key,
                                Name = r.Value.Name,
                                ShortDescription = new SarifMessage { Text = r.Value.Description },
                            }).ToList(),
                        },
                    },
                    Results = report.Targets.SelectMany(t => t.Findings).Select(ToResult).ToList(),
                },
            ],
        };
        return JsonSerializer.Serialize(sarif, JsonSettings.Create());
    }

    private static SarifResult ToResult(Finding finding)
    {
        return new SarifResult
        {
            RuleId = finding.RuleId,
            Level = finding.Severity switch
            {
                "high" => "error",
                "medium" => "warning",
                _ => "note",
            },
            Message = new SarifMessage { Text = finding.Message },
            Locations =
            [
                new SarifLocation
                {
                    PhysicalLocation = new SarifPhysicalLocation
                    {
                        ArtifactLocation = new SarifArtifactLocation { Uri = finding.File },
                        Region = new SarifRegion { StartLine = 1 },
                    },
                    LogicalLocations =
                    [
                        new SarifLogicalLocation
                        {
                            FullyQualifiedName = finding.Method ?? finding.Type ?? finding.Assembly ?? finding.File,
                        },
                    ],
                },
            ],
        };
    }
}

sealed class SarifLog
{
    public string Version { get; init; } = "2.1.0";
    public string Schema { get; init; } = "https://json.schemastore.org/sarif-2.1.0.json";
    public List<SarifRun> Runs { get; init; } = [];
}

sealed class SarifRun
{
    public SarifTool Tool { get; init; } = new();
    public List<SarifResult> Results { get; init; } = [];
}

sealed class SarifTool
{
    public SarifDriver Driver { get; init; } = new();
}

sealed class SarifDriver
{
    public string Name { get; init; } = "";
    public string Version { get; init; } = "";
    public List<SarifRule> Rules { get; init; } = [];
}

sealed class SarifRule
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public SarifMessage ShortDescription { get; init; } = new();
}

sealed class SarifResult
{
    public string RuleId { get; init; } = "";
    public string Level { get; init; } = "warning";
    public SarifMessage Message { get; init; } = new();
    public List<SarifLocation> Locations { get; init; } = [];
}

sealed class SarifMessage
{
    public string Text { get; init; } = "";
}

sealed class SarifLocation
{
    public SarifPhysicalLocation PhysicalLocation { get; init; } = new();
    public List<SarifLogicalLocation> LogicalLocations { get; init; } = [];
}

sealed class SarifPhysicalLocation
{
    public SarifArtifactLocation ArtifactLocation { get; init; } = new();
    public SarifRegion Region { get; init; } = new();
}

sealed class SarifArtifactLocation
{
    public string Uri { get; init; } = "";
}

sealed class SarifRegion
{
    public int StartLine { get; init; } = 1;
}

sealed class SarifLogicalLocation
{
    public string FullyQualifiedName { get; init; } = "";
}
