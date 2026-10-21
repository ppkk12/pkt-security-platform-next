using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace PktSecurity.Domain.Services;

public static class FingerprintCalculator
{
    public static string ComputePrimary(string toolName, string ruleOrCve, string? filePathOrPurl, int? lineNumber)
    {
        var normalizedPath = (filePathOrPurl ?? string.Empty).Replace('\\', '/').Trim().ToLowerInvariant();
        var raw = $"{toolName.Trim().ToLowerInvariant()}|{ruleOrCve.Trim()}|{normalizedPath}|{lineNumber ?? 0}";
        return ComputeSha256Hex(raw);
    }

    public static string ComputeSecondary(
        Guid tenantId,
        Guid projectId,
        string category,
        string cweOrCve,
        string? filePath,
        string? enclosingSymbol,
        string? codeSnippet)
    {
        var normalizedPath = (filePath ?? string.Empty).Replace('\\', '/').Trim().ToLowerInvariant();
        var symbol = (enclosingSymbol ?? string.Empty).Trim();
        var tokenHash = ComputeNormalizedTokenHash(codeSnippet ?? string.Empty);
        var raw = $"{tenantId}|{projectId}|{category.Trim().ToUpperInvariant()}|{cweOrCve.Trim().ToUpperInvariant()}|{normalizedPath}|{symbol}|{tokenHash}";
        return ComputeSha256Hex(raw);
    }

    private static readonly string EmptyHash = ComputeSha256Hex(string.Empty);

    public static string ComputeNormalizedTokenHash(string codeSnippet)
    {
        if (string.IsNullOrWhiteSpace(codeSnippet))
            return EmptyHash;

        // Strip single line comments and multi-line comments
        var noComments = Regex.Replace(codeSnippet, @"//.*|/\*[\s\S]*?\*/|#.*", string.Empty);
        // Normalize all whitespace to single space
        var normalized = Regex.Replace(noComments, @"\s+", " ").Trim();
        return ComputeSha256Hex(normalized);
    }

    private static string ComputeSha256Hex(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
