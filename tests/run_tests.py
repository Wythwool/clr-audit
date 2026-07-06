import json
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "artifacts" / "tests"
TOOL = ROOT / "src" / "clr-audit.csproj"


SAMPLE_CSPROJ = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <NoWarn>SYSLIB0011</NoWarn>
  </PropertyGroup>
</Project>
"""


SAMPLE_CODE = r"""
using System;
using System.Diagnostics;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;
using System.Runtime.Serialization.Formatters.Binary;

public static class RiskySample
{
    [DllImport("kernel32.dll")]
    private static extern IntPtr LoadLibrary(string name);

    public static void Run(byte[] payload)
    {
        Assembly.Load(payload);
        Process.Start("cmd.exe");
        _ = new BinaryFormatter();
        _ = new DynamicMethod("x", typeof(void), Type.EmptyTypes);
        _ = Convert.FromBase64String("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWkFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFla");
        Console.WriteLine("https://example.test/payload");
        LoadLibrary("demo.dll");
    }

    public sealed class Nested
    {
        public static void Again(byte[] payload)
        {
            Assembly.Load(payload);
        }
    }
}
"""


def run(cmd, check=True, cwd=ROOT):
    result = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    if check and result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit(result.returncode)
    return result


def build_sample():
    sample_dir = WORK / "RiskySample"
    sample_dir.mkdir(parents=True, exist_ok=True)
    (sample_dir / "RiskySample.csproj").write_text(SAMPLE_CSPROJ, encoding="utf-8")
    (sample_dir / "RiskySample.cs").write_text(SAMPLE_CODE, encoding="utf-8")
    run(["dotnet", "build", "RiskySample.csproj", "-c", "Release"], cwd=sample_dir)
    return sample_dir / "bin" / "Release" / "net8.0" / "RiskySample.dll"


def main():
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)

    run(["dotnet", "build", str(TOOL), "-c", "Release"])
    sample = build_sample()
    out_dir = WORK / "out"
    out_dir.mkdir()
    json_out = out_dir / "report.json"
    sarif_out = out_dir / "report.sarif"
    csv_out = out_dir / "findings.csv"
    md_out = out_dir / "report.md"

    result = run(
        [
            "dotnet",
            "run",
            "--project",
            str(TOOL),
            "-c",
            "Release",
            "--",
            "audit",
            str(sample),
            "--json-out",
            str(json_out),
            "--sarif-out",
            str(sarif_out),
            "--csv-out",
            str(csv_out),
            "--md-out",
            str(md_out),
        ]
    )
    assert result.stdout == ""

    report = json.loads(json_out.read_text(encoding="utf-8-sig"))
    rules = {finding["ruleId"] for target in report["targets"] for finding in target["findings"]}
    assert report["summary"]["files"] == 1
    assert report["summary"]["scanned"] == 1
    assert report["summary"]["high"] >= 2
    assert "R_ASSEMBLY_LOAD" in rules
    assert "R_PINVOKE" in rules
    assert "R_PROCESS_START" in rules
    assert "R_BINARY_FORMATTER" in rules
    assert "R_REFLECTION_EMIT" in rules
    assert "R_ENCODED_STRING" in rules
    assert "R_URL_LITERAL" in rules
    assert any("Nested" in finding.get("method", "") for target in report["targets"] for finding in target["findings"])

    assert json.loads(sarif_out.read_text(encoding="utf-8-sig"))["runs"][0]["results"]
    assert "R_ASSEMBLY_LOAD" in csv_out.read_text(encoding="utf-8-sig")
    assert "| Files |" in md_out.read_text(encoding="utf-8-sig")

    fail = run(
        [
            "dotnet",
            "run",
            "--project",
            str(TOOL),
            "-c",
            "Release",
            "--",
            "audit",
            str(sample),
            "--fail-on",
            "high",
        ],
        check=False,
    )
    assert fail.returncode == 3
    assert json.loads(fail.stdout)["summary"]["high"] >= 1

    directory = run(
        [
            "dotnet",
            "run",
            "--project",
            str(TOOL),
            "-c",
            "Release",
            "--",
            "audit",
            str(sample.parent.parent.parent),
            "--recursive",
        ],
        check=True,
    )
    dir_report = json.loads(directory.stdout)
    assert dir_report["summary"]["files"] >= 1


if __name__ == "__main__":
    main()
