using PktSecurity.Application.Common.Interfaces;
using PktSecurity.Application.DTOs;
using PktSecurity.Infrastructure.Parsers;

namespace PktSecurity.Infrastructure.Scanners;

public abstract class BaseCliScannerAdapter : IScannerAdapter
{
    protected readonly ISandboxExecutionProvider _sandbox;
    protected readonly SarifStreamingParser _parser;
    protected readonly string _cliExecutableName;

    protected BaseCliScannerAdapter(
        ISandboxExecutionProvider sandbox,
        SarifStreamingParser parser,
        string cliExecutableName)
    {
        _sandbox = sandbox;
        _parser = parser;
        _cliExecutableName = cliExecutableName;
    }

    public abstract string ScannerName { get; }

    public virtual bool IsAvailable()
    {
        try
        {
            var paths = (Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(Path.PathSeparator);
            var exeName = OperatingSystem.IsWindows() ? $"{_cliExecutableName}.exe" : _cliExecutableName;
            return paths.Any(p => File.Exists(Path.Combine(p, exeName)) || File.Exists(Path.Combine(p, _cliExecutableName)));
        }
        catch
        {
            return false;
        }
    }

    public abstract Task<ScannerExecutionResult> ScanAsync(
        ScannerScanContext context,
        CancellationToken cancellationToken = default);

    protected async Task<IReadOnlyList<NormalizedFindingDto>> ParseSarifOutputFileAsync(
        string sarifPath,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(sarifPath))
            return Array.Empty<NormalizedFindingDto>();

        var findings = new List<NormalizedFindingDto>();
        await using var stream = File.OpenRead(sarifPath);
        await foreach (var item in _parser.ParseAsync(stream, cancellationToken))
        {
            findings.Add(item);
        }

        return findings;
    }
}

public class GitleaksScannerAdapter : BaseCliScannerAdapter
{
    public GitleaksScannerAdapter(ISandboxExecutionProvider sandbox, SarifStreamingParser parser)
        : base(sandbox, parser, "gitleaks")
    {
    }

    public override string ScannerName => "gitleaks";

    public override async Task<ScannerExecutionResult> ScanAsync(
        ScannerScanContext context,
        CancellationToken cancellationToken = default)
    {
        var outputDir = Path.GetDirectoryName(context.OutputFilePath);
        if (!string.IsNullOrEmpty(outputDir)) Directory.CreateDirectory(outputDir);

        var args = new[]
        {
            "dir",
            context.TargetDirectory,
            "--report-path", context.OutputFilePath,
            "--report-format", "sarif",
            "--no-banner",
            "--exit-code", "0"
        };

        var request = new SandboxExecutionRequest(
            ExecutablePath: "gitleaks",
            Arguments: args,
            WorkingDirectory: context.TargetDirectory,
            Timeout: TimeSpan.FromMinutes(5));

        var execResult = await _sandbox.ExecuteAsync(request, cancellationToken);
        var findings = await ParseSarifOutputFileAsync(context.OutputFilePath, cancellationToken);

        return new ScannerExecutionResult(
            ScannerName,
            execResult.ExitCode == 0 || findings.Count > 0,
            context.OutputFilePath,
            execResult.ExitCode != 0 && findings.Count == 0 ? execResult.StandardError : null,
            findings);
    }
}

public class TrivyScannerAdapter : BaseCliScannerAdapter
{
    public TrivyScannerAdapter(ISandboxExecutionProvider sandbox, SarifStreamingParser parser)
        : base(sandbox, parser, "trivy")
    {
    }

    public override string ScannerName => "trivy";

    public override async Task<ScannerExecutionResult> ScanAsync(
        ScannerScanContext context,
        CancellationToken cancellationToken = default)
    {
        var outputDir = Path.GetDirectoryName(context.OutputFilePath);
        if (!string.IsNullOrEmpty(outputDir)) Directory.CreateDirectory(outputDir);

        var args = new[]
        {
            "fs",
            "--format", "sarif",
            "--output", context.OutputFilePath,
            "--exit-code", "0",
            context.TargetDirectory
        };

        var request = new SandboxExecutionRequest(
            ExecutablePath: "trivy",
            Arguments: args,
            WorkingDirectory: context.TargetDirectory,
            Timeout: TimeSpan.FromMinutes(5));

        var execResult = await _sandbox.ExecuteAsync(request, cancellationToken);
        var findings = await ParseSarifOutputFileAsync(context.OutputFilePath, cancellationToken);

        return new ScannerExecutionResult(
            ScannerName,
            execResult.ExitCode == 0 || findings.Count > 0,
            context.OutputFilePath,
            execResult.ExitCode != 0 && findings.Count == 0 ? execResult.StandardError : null,
            findings);
    }
}

public class SemgrepScannerAdapter : BaseCliScannerAdapter
{
    public SemgrepScannerAdapter(ISandboxExecutionProvider sandbox, SarifStreamingParser parser)
        : base(sandbox, parser, "semgrep")
    {
    }

    public override string ScannerName => "semgrep";

    public override async Task<ScannerExecutionResult> ScanAsync(
        ScannerScanContext context,
        CancellationToken cancellationToken = default)
    {
        var outputDir = Path.GetDirectoryName(context.OutputFilePath);
        if (!string.IsNullOrEmpty(outputDir)) Directory.CreateDirectory(outputDir);

        var args = new[]
        {
            "scan",
            "--config", "auto",
            "--sarif",
            "--output", context.OutputFilePath,
            context.TargetDirectory
        };

        var request = new SandboxExecutionRequest(
            ExecutablePath: "semgrep",
            Arguments: args,
            WorkingDirectory: context.TargetDirectory,
            Timeout: TimeSpan.FromMinutes(5));

        var execResult = await _sandbox.ExecuteAsync(request, cancellationToken);
        var findings = await ParseSarifOutputFileAsync(context.OutputFilePath, cancellationToken);

        return new ScannerExecutionResult(
            ScannerName,
            execResult.ExitCode == 0 || findings.Count > 0,
            context.OutputFilePath,
            execResult.ExitCode != 0 && findings.Count == 0 ? execResult.StandardError : null,
            findings);
    }
}

public class ScannerRegistry
{
    private readonly IEnumerable<IScannerAdapter> _adapters;
    private readonly NativeScannerAdapter _nativeAdapter;

    public ScannerRegistry(IEnumerable<IScannerAdapter> adapters, NativeScannerAdapter nativeAdapter)
    {
        _adapters = adapters;
        _nativeAdapter = nativeAdapter;
    }

    public IScannerAdapter GetAdapter(string scannerName)
    {
        var normalized = scannerName.Trim().ToLowerInvariant();
        var adapter = _adapters.FirstOrDefault(a => a.ScannerName.Equals(normalized, StringComparison.OrdinalIgnoreCase));

        if (adapter != null && adapter.IsAvailable())
        {
            return adapter;
        }

        // Graceful fallback to deterministic native adapter
        return _nativeAdapter;
    }
}
