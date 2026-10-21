using System.Diagnostics;
using System.Text;
using PktSecurity.Application.Common.Interfaces;

namespace PktSecurity.Infrastructure.Sandbox;

public class ProcessSandboxExecutionProvider : ISandboxExecutionProvider
{
    public async Task<SandboxExecutionResult> ExecuteAsync(
        SandboxExecutionRequest request,
        CancellationToken cancellationToken = default)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = request.ExecutablePath,
            WorkingDirectory = request.WorkingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        // Clear environment variables to prevent host secrets from leaking
        startInfo.Environment.Clear();
        startInfo.Environment["PATH"] = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        startInfo.Environment["TEMP"] = Path.GetTempPath();
        startInfo.Environment["TMP"] = Path.GetTempPath();

        // Add caller-specified environment variables if any
        if (request.EnvironmentVariables != null)
        {
            foreach (var kvp in request.EnvironmentVariables)
            {
                startInfo.Environment[kvp.Key] = kvp.Value;
            }
        }

        // Add arguments via ArgumentList (strictly zero shell concatenation)
        foreach (var arg in request.Arguments)
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
                    stderrBuilder.ToString() + (isTimeout ? "\nProcess timed out and was killed." : "\nProcess was cancelled."),
                    stopwatch.Elapsed,
                    TimedOut: isTimeout);
            }
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            return new SandboxExecutionResult(
                -1,
                string.Empty,
                $"Failed to start process: {ex.Message}",
                stopwatch.Elapsed,
                TimedOut: false);
        }
    }
}
