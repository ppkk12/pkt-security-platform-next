using PktSecurity.Application.Common.Interfaces;
using PktSecurity.Application.DTOs;
using PktSecurity.Domain.Enums;

namespace PktSecurity.Infrastructure.Services;

public class RuleBasedRemediationProvider : IAiRemediationProvider
{
    public string ProviderName => "RuleBased";

    public Task<RemediationSuggestion> GenerateRemediationAsync(
        RemediationContext context,
        CancellationToken cancellationToken = default)
    {
        var suggestion = new RemediationSuggestion();

        // 1. Verified facts (objective scanner data)
        suggestion.VerifiedFacts.Add($"Scanner: {context.ScannerName}");
        suggestion.VerifiedFacts.Add($"Category: {context.Category}");
        if (!string.IsNullOrEmpty(context.CweId)) suggestion.VerifiedFacts.Add($"CWE: {context.CweId}");
        if (!string.IsNullOrEmpty(context.CveId)) suggestion.VerifiedFacts.Add($"CVE: {context.CveId}");
        if (!string.IsNullOrEmpty(context.FilePath)) suggestion.VerifiedFacts.Add($"File: {context.FilePath}:{context.StartLine}");
        if (!string.IsNullOrEmpty(context.PackagePurl)) suggestion.VerifiedFacts.Add($"Package: {context.PackagePurl} (Current: {context.InstalledVersion ?? "unknown"}, Target: {context.FixedVersion ?? "latest"})");

        var filePath = context.FilePath ?? "src/vulnerable_file.cs";
        var relativePath = filePath.Replace('\\', '/');

        // 2. Specific vulnerability patterns
        if (context.CweId == "CWE-89" || context.Title.Contains("SQL Injection", StringComparison.OrdinalIgnoreCase))
        {
            suggestion.AiHypothesisAnalysis =
                "Vulnerability mechanism: Direct concatenation or string interpolation of user-supplied input into SQL command strings allows attackers to break syntax boundaries and execute arbitrary SQL commands (CWE-89). " +
                "Impact: Potential data exfiltration, tampering, or privilege escalation.";

            suggestion.SideEffectsWarning =
                "Ensure that query parameter names match existing column mappings and that null values are handled appropriately.";

            suggestion.ProposedUnifiedDiff =
$@"--- a/{relativePath}
+++ b/{relativePath}
@@ -10,3 +10,4 @@
-var query = $""SELECT * FROM Users WHERE Username = '{{username}}' AND Password = '{{password}}'"";
-using var cmd = new NpgsqlCommand(query, conn);
+var query = ""SELECT * FROM Users WHERE Username = @username AND Password = @password"";
+using var cmd = new NpgsqlCommand(query, conn);
+cmd.Parameters.AddWithValue(""@username"", username);
+cmd.Parameters.AddWithValue(""@password"", password);";
        }
        else if (context.CweId == "CWE-78" || context.Title.Contains("Command Injection", StringComparison.OrdinalIgnoreCase))
        {
            suggestion.AiHypothesisAnalysis =
                "Vulnerability mechanism: User-controlled input is passed directly to an operating system shell or command interpreter (CWE-78). " +
                "Impact: An attacker can append arbitrary shell command metacharacters (e.g. ';', '|', '&') to achieve remote code execution in the application context.";

            suggestion.SideEffectsWarning =
                "Switching from shell execution to direct process argument lists disables shell built-in expansions, pipes, and wildcards. Verify that the command does not rely on shell features.";

            suggestion.ProposedUnifiedDiff =
$@"--- a/{relativePath}
+++ b/{relativePath}
@@ -12,3 +12,4 @@
-var psi = new ProcessStartInfo(""cmd.exe"", $""/c dir {{userInput}}"") {{ UseShellExecute = true }};
-Process.Start(psi);
+var psi = new ProcessStartInfo(""dir"") {{ UseShellExecute = false, CreateNoWindow = true }};
+psi.ArgumentList.Add(userInput);
+Process.Start(psi);";
        }
        else if (context.Category == FindingCategory.SCA && !string.IsNullOrEmpty(context.FixedVersion))
        {
            var targetVer = context.FixedVersion;
            var currentVer = context.InstalledVersion ?? "0.0.0";

            suggestion.AiHypothesisAnalysis =
                $"Vulnerability mechanism: Dependency '{context.PackagePurl ?? context.Title}' contains known security defect '{context.CveId}'. " +
                $"Remediation: Upgrade the dependency from version '{currentVer}' to fixed version '{targetVer}'.";

            suggestion.SideEffectsWarning =
                "Dependency version upgrades may include breaking changes or modified dependency trees. Ensure full regression tests pass.";

            var depFile = relativePath.EndsWith(".json") ? relativePath : "package.json";
            suggestion.ProposedUnifiedDiff =
$@"--- a/{depFile}
+++ b/{depFile}
@@ -5,3 +5,3 @@
-    ""lodash"": ""^{currentVer}""
+    ""lodash"": ""^{targetVer}""";
        }
        else
        {
            suggestion.AiHypothesisAnalysis =
                $"Security analysis for {context.Title}: Input validation and defensive boundary controls are required to neutralize the risk identified by rule {context.CweId ?? context.CveId ?? context.ScannerName}.";

            suggestion.SideEffectsWarning =
                "Verify integration tests against edge cases including null, empty, and boundary-value inputs.";

            suggestion.ProposedUnifiedDiff =
$@"--- a/{relativePath}
+++ b/{relativePath}
@@ -1,3 +1,4 @@
+// Security patch applied by PktSecurity deterministic remediation engine
+if (string.IsNullOrWhiteSpace(input)) throw new ArgumentException(""Invalid input"");";
        }

        return Task.FromResult(suggestion);
    }
}
