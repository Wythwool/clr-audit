# clr-audit

`clr-audit` is an offline .NET IL auditor for triaging managed assemblies. It reads `.dll` and `.exe` files with Mono.Cecil and reports patterns often seen in loaders, droppers, plugins with native escape hatches, and risky enterprise code.

Checks include:

- dynamic assembly loading: `Assembly.Load`, `LoadFrom`, `LoadFile`
- P/Invoke imports and native library loading
- `Process.Start`
- `BinaryFormatter`
- `Reflection.Emit`, `DynamicMethod`, and dispatch proxies
- IL `calli`
- native pointer marshaling
- network fetch APIs
- long base64-like strings and URL literals
- embedded resources with executable-looking names

The tool reads assemblies as files only. It does not execute target code.

## Build

```bash
dotnet build src/clr-audit.csproj -c Release
```

## Run

```bash
dotnet run --project src/clr-audit.csproj -c Release -- audit target.dll
dotnet run --project src/clr-audit.csproj -c Release -- audit samples -r \
  --json-out out/report.json \
  --sarif-out out/report.sarif \
  --csv-out out/findings.csv \
  --md-out out/report.md
```

Use `--fail-on high`, `--fail-on medium`, or `--fail-on low` to return exit code `3` when findings at that level or above are present.

Exit codes:

- `0` scan completed
- `1` command-line error or no inputs found
- `3` `--fail-on` threshold matched

## Report

JSON is the default output. SARIF, CSV, and Markdown are optional file outputs. Each finding includes:

- rule id and severity
- file and assembly name
- type and method symbol
- IL offset
- target API/string/resource when available

## Tests

```bash
python tests/run_tests.py
```

The test harness builds a generated risky .NET assembly, scans it, checks JSON/SARIF/CSV/Markdown outputs, verifies nested type scanning, and checks `--fail-on`.

CI builds and tests on Windows and Linux with .NET 8.
