using System.Security.Cryptography;
using System.Text;

namespace PktSecurity.Domain.Services;

public static class AuditHashCalculator
{
    public static string ComputeEventHash(
        string prevEventHash,
        Guid tenantId,
        string eventType,
        Guid? userId,
        string action,
        string detailsJson,
        DateTime createdAtUtc)
    {
        var canonical = $"{prevEventHash}|{tenantId}|{eventType.Trim()}|{userId?.ToString() ?? "system"}|{action.Trim()}|{detailsJson.Trim()}|{createdAtUtc.ToString("O")}";
        var bytes = Encoding.UTF8.GetBytes(canonical);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
