using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace PktSecurity.Infrastructure.Security;

public static class SecretRedactor
{
    private static readonly Regex CommonTokenRegex = new(
        @"(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|xox[baprs]-[0-9a-zA-Z]{10,48}|ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})",
        RegexOptions.Compiled);

    public static string Redact(string? secret)
    {
        if (string.IsNullOrEmpty(secret))
            return string.Empty;

        if (secret.Length <= 5)
            return new string('*', secret.Length);

        var prefix = secret[..3];
        var suffix = secret[^2..];
        var maskedMiddle = new string('*', secret.Length - 5);

        return $"{prefix}{maskedMiddle}{suffix}";
    }

    public static string RedactText(string text)
    {
        if (string.IsNullOrEmpty(text))
            return string.Empty;

        return CommonTokenRegex.Replace(text, match => Redact(match.Value));
    }

    public static string ComputeHmacSha256(string secret, string key)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key));
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(secret));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
