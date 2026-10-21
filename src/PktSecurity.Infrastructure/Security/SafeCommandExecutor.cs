using System.Diagnostics;
using System.Text.RegularExpressions;

namespace PktSecurity.Infrastructure.Security;

public static class ArgumentValidator
{
    private static readonly Regex SafeBranchRegex = new(@"^[a-zA-Z0-9_\-\./]+$", RegexOptions.Compiled);
    private static readonly Regex DangerousCharsRegex = new(@"[;&|`$\r\n\t]", RegexOptions.Compiled);

    public static void ValidateGitBranch(string branch)
    {
        if (string.IsNullOrWhiteSpace(branch))
            throw new SecurityViolationException("CommandInjection_EmptyBranch", "Branch name cannot be empty.");

        if (branch.StartsWith("-", StringComparison.Ordinal))
            throw new SecurityViolationException("ArgumentInjection_LeadingDash", $"Branch name '{branch}' cannot begin with a dash (-).");

        if (DangerousCharsRegex.IsMatch(branch))
            throw new SecurityViolationException("CommandInjection_DangerousCharacters", $"Branch name contains prohibited command characters: '{branch}'.");

        if (!SafeBranchRegex.IsMatch(branch))
            throw new SecurityViolationException("CommandInjection_InvalidFormat", $"Branch name '{branch}' violates allowed character set.");
    }

    public static void ValidateGitUrl(string url)
    {
        if (string.IsNullOrWhiteSpace(url))
            throw new SecurityViolationException("CommandInjection_EmptyUrl", "Repository URL cannot be empty.");

        if (url.StartsWith("-", StringComparison.Ordinal))
            throw new SecurityViolationException("ArgumentInjection_LeadingDash", $"Repository URL '{url}' cannot begin with a dash (-).");

        if (DangerousCharsRegex.IsMatch(url))
            throw new SecurityViolationException("CommandInjection_DangerousCharacters", $"Repository URL contains prohibited command characters: '{url}'.");

        // Disallow dangerous git protocol options (e.g. ext::)
        if (url.StartsWith("ext::", StringComparison.OrdinalIgnoreCase))
            throw new SecurityViolationException("CommandInjection_ExtProtocol", "Git ext:: protocol is strictly prohibited.");
    }

    public static void ValidateSafeArgument(string argument, string argumentName = "argument")
    {
        if (string.IsNullOrWhiteSpace(argument))
            return;

        if (DangerousCharsRegex.IsMatch(argument))
        {
            throw new SecurityViolationException(
                "CommandInjection_DangerousCharacters",
                $"Parameter '{argumentName}' contains prohibited command characters: '{argument}'.");
        }
    }
}

public static class SafeCommandExecutor
{
    public record ExecutionResult(int ExitCode, string StandardOutput, string StandardError);

    public static async Task<ExecutionResult> ExecuteAsync(
        string executablePath,
        IEnumerable<string> arguments,
        string? workingDirectory = null,
        IDictionary<string, string?>? environmentVariables = null,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        var psi = new ProcessStartInfo
        {
            FileName = executablePath,
            UseShellExecute = false, // Strictly prohibited to use shell execute
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        if (!string.IsNullOrEmpty(workingDirectory))
        {
            psi.WorkingDirectory = workingDirectory;
        }

        foreach (var arg in arguments)
        {
            psi.ArgumentList.Add(arg);
        }

        if (environmentVariables != null)
        {
            foreach (var kvp in environmentVariables)
            {
                if (kvp.Value == null)
                    psi.Environment.Remove(kvp.Key);
                else
                    psi.Environment[kvp.Key] = kvp.Value;
            }
        }

        using var process = new Process { StartInfo = psi };
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (timeout.HasValue)
        {
            cts.CancelAfter(timeout.Value);
        }

        try
        {
            process.Start();

            var stdoutTask = process.StandardOutput.ReadToEndAsync(cts.Token);
            var stderrTask = process.StandardError.ReadToEndAsync(cts.Token);

            await process.WaitForExitAsync(cts.Token);

            var stdout = await stdoutTask;
            var stderr = await stderrTask;

            return new ExecutionResult(process.ExitCode, stdout, stderr);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException($"Process '{executablePath}' timed out after {timeout?.TotalSeconds} seconds.");
        }
        catch
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw;
        }
    }
}
