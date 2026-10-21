namespace PktSecurity.Application.Common.Interfaces;

public record SandboxExecutionRequest(
    string ExecutablePath,
    IReadOnlyList<string> Arguments,
    string WorkingDirectory,
    TimeSpan Timeout,
    IReadOnlyDictionary<string, string>? EnvironmentVariables = null,
    int? MemoryLimitMb = null,
    int? CpuQuotaPercent = null);

public record SandboxExecutionResult(
    int ExitCode,
    string StandardOutput,
    string StandardError,
    TimeSpan ExecutionDuration,
    bool TimedOut);

public interface ISandboxExecutionProvider
{
    Task<SandboxExecutionResult> ExecuteAsync(
        SandboxExecutionRequest request,
        CancellationToken cancellationToken = default);
}
