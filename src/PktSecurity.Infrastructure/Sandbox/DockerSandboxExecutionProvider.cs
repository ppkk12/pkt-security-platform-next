using System.Diagnostics;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PktSecurity.Application.Common.Interfaces;

namespace PktSecurity.Infrastructure.Sandbox;

public class DockerSandboxOptions
{
    public const string SectionName = "Sandbox:Docker";

    public string Image { get; set; } = "pkt-scanner-runner:latest";
    public bool EnableGvisor { get; set; } = false;
    public string MemoryLimit { get; set; } = "2g";
    public string CpuLimit { get; set; } = "2";
    public int PidsLimit { get; set; } = 256;
    public string DockerBinaryPath { get; set; } = "docker";
}

public class DockerSandboxExecutionProvider : ISandboxExecutionProvider
{
    private readonly DockerSandboxOptions _options;
    private readonly ILogger<DockerSandboxExecutionProvider>? _logger;

    public DockerSandboxExecutionProvider(
        IOptions<DockerSandboxOptions>? options = null,
        ILogger<DockerSandboxExecutionProvider>? logger = null)
    {
        _options = options?.Value ?? new DockerSandboxOptions();
        _logger = logger;
    }

    public List<string> BuildDockerArguments(SandboxExecutionRequest request)
    {
        var args = new List<string>
        {
            "run",
            "--rm",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            $"--pids-limit={_options.PidsLimit}",
            $"--memory={(!string.IsNullOrWhiteSpace(request.MemoryLimitMb?.ToString()) ? $"{request.MemoryLimitMb}m" : _options.MemoryLimit)}",
            $"--cpus={_options.CpuLimit}"
        };

        if (_options.EnableGvisor)
        {
            args.Add("--runtime=runsc");
        }

        // Tmpfs for temporary files
        args.Add("--tmpfs");
        args.Add("/tmp:rw,noexec,nosuid,size=512m");

        // Workspace volume mount (Read-Only)
        var hostWorkspace = Path.GetFullPath(request.WorkingDirectory);
        args.Add("-v");
        args.Add($"{hostWorkspace}:/workspace:ro");
        args.Add("-w");
        args.Add("/workspace");

        // Environment variables
        if (request.EnvironmentVariables != null)
        {
            foreach (var kvp in request.EnvironmentVariables)
            {
                args.Add("-e");
                args.Add($"{kvp.Key}={kvp.Value}");
            }
        }

        // Image
        args.Add(_options.Image);

        // Executable & Target command arguments
        args.Add(request.ExecutablePath);
        args.AddRange(request.Arguments);

        return args;
    }

    public async Task<SandboxExecutionResult> ExecuteAsync(
        SandboxExecutionRequest request,
        CancellationToken cancellationToken = default)
    {
        var dockerArgs = BuildDockerArguments(request);

        var startInfo = new ProcessStartInfo
        {
            FileName = _options.DockerBinaryPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        foreach (var arg in dockerArgs)
        {
            startInfo.ArgumentList.Add(arg);
        }

        var stdoutBuilder = new StringBuilder();
        var stderrBuilder = new StringBuilder();

        using var process = new Process { StartInfo = startInfo };

        process.OutputDataReceived += (_, e) =>
        {
            if (e.Data != null) stdoutBuilder.AppendLine(e.Data);
        };
        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data != null) stderrBuilder.AppendLine(e.Data);
        };

        var stopwatch = Stopwatch.StartNew();

        try
        {
            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            using var timeoutCts = new CancellationTokenSource(request.Timeout);
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

            try
            {
                await process.WaitForExitAsync(linkedCts.Token);
                stopwatch.Stop();

                return new SandboxExecutionResult(
                    process.ExitCode,
                    stdoutBuilder.ToString(),
                    stderrBuilder.ToString(),
                    stopwatch.Elapsed,
                    TimedOut: false);
            }
            catch (OperationCanceledException)
            {
                stopwatch.Stop();
                try
                {
                    if (!process.HasExited)
                    {
                        process.Kill(entireProcessTree: true);
                    }
                }
                catch
                {
                    // Ignore kill errors
                }

                var isTimeout = timeoutCts.IsCancellationRequested;
                return new SandboxExecutionResult(
                    -1,
                    stdoutBuilder.ToString(),
                    stderrBuilder.ToString() + (isTimeout ? "\nDocker sandbox process timed out and was killed." : "\nDocker sandbox process was cancelled."),
                    stopwatch.Elapsed,
                    TimedOut: isTimeout);
            }
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            _logger?.LogError(ex, "Failed to start Docker sandbox process");
            return new SandboxExecutionResult(
                -1,
                string.Empty,
                $"Failed to start Docker sandbox process: {ex.Message}",
                stopwatch.Elapsed,
                TimedOut: false);
        }
    }
}
