# clr-audit — .NET IL auditor (C#)

**What:** Scans .NET assemblies for risky IL patterns: `Assembly.Load(byte[])`, `LoadFrom/File`, P/Invoke, `Process.Start`, `BinaryFormatter` use, `Reflection.Emit`/`DynamicMethod`/`calli`.  
**Output:** JSON and SARIF for CI.

## Build
```bash
dotnet build -c Release
```

## Run
```bash
dotnet run -c Release -- audit path/to/dir_or_dll [-r] --json-out out.json --sarif-out out.sarif
```
