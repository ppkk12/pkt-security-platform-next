using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using PktSecurity.Application.Common.Interfaces;
using PktSecurity.Application.DTOs;
using PktSecurity.Domain.Entities;
using PktSecurity.Infrastructure.Data;

namespace PktSecurity.Infrastructure.Services;

public class AuditService : IAuditService
{
    private const string GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000";
    private readonly AppDbContext _context;

    public AuditService(AppDbContext context)
    {
        _context = context;
    }

    public async Task<AuditEvent> RecordEventAsync(
        Guid tenantId,
        string eventType,
        Guid? userId,
        string action,
        object details,
        CancellationToken cancellationToken = default)
    {
        var detailsJson = details is string str ? str : JsonSerializer.Serialize(details);

        // Fetch latest event for this tenant to chain
        var latestEvent = await _context.AuditEvents
            .Where(e => e.TenantId == tenantId)
            .OrderByDescending(e => e.CreatedAt)
            .ThenByDescending(e => e.Id)
            .FirstOrDefaultAsync(cancellationToken);

        var prevHash = latestEvent?.EventHash ?? GenesisHash;
        
        // Truncate to microsecond precision (PostgreSQL timestamp with time zone standard: 1 tick = 100ns, 10 ticks = 1 microsecond)
        var nowTicks = DateTime.UtcNow.Ticks;
        var createdAt = new DateTime(nowTicks - (nowTicks % 10), DateTimeKind.Utc);

        var auditEvent = new AuditEvent
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            EventType = eventType,
            UserId = userId,
            Action = action,
            DetailsJson = detailsJson,
            PrevEventHash = prevHash,
            CreatedAt = createdAt
        };

        var canonicalPayload = ComputeCanonicalPayload(
            auditEvent.Id,
            tenantId,
            eventType,
            userId,
            action,
            detailsJson,
            createdAt);

        auditEvent.EventHash = ComputeHash(prevHash, canonicalPayload);

        _context.AuditEvents.Add(auditEvent);
        await _context.SaveChangesAsync(cancellationToken);

        return auditEvent;
    }

    public async Task<AuditVerificationResultDto> VerifyChainAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default)
    {
        var events = await _context.AuditEvents
            .Where(e => e.TenantId == tenantId)
            .OrderBy(e => e.CreatedAt)
            .ThenBy(e => e.Id)
            .ToListAsync(cancellationToken);

        if (events.Count == 0)
        {
            return new AuditVerificationResultDto
            {
                IsValid = true,
                TotalEvents = 0
            };
        }

        string expectedPrevHash = GenesisHash;

        for (int i = 0; i < events.Count; i++)
        {
            var ev = events[i];

            // 1. Check previous hash continuity
            if (ev.PrevEventHash != expectedPrevHash)
            {
                return new AuditVerificationResultDto
                {
                    IsValid = false,
                    TotalEvents = events.Count,
                    BrokenEventId = ev.Id,
                    BrokenReason = $"Broken hash chain at index {i}: expected PrevEventHash '{expectedPrevHash}' but found '{ev.PrevEventHash}'"
                };
            }

            // 2. Recompute hash from canonical fields
            var canonicalPayload = ComputeCanonicalPayload(
                ev.Id,
                ev.TenantId,
                ev.EventType,
                ev.UserId,
                ev.Action,
                ev.DetailsJson,
                ev.CreatedAt);

            var computedHash = ComputeHash(ev.PrevEventHash, canonicalPayload);

            if (ev.EventHash != computedHash)
            {
                return new AuditVerificationResultDto
                {
                    IsValid = false,
                    TotalEvents = events.Count,
                    BrokenEventId = ev.Id,
                    BrokenReason = $"Tampered payload detected at event {ev.Id}: recorded EventHash '{ev.EventHash}' does not match computed '{computedHash}'"
                };
            }

            expectedPrevHash = ev.EventHash;
        }

        return new AuditVerificationResultDto
        {
            IsValid = true,
            TotalEvents = events.Count
        };
    }

    public async Task<IReadOnlyList<AuditEventDto>> GetAuditEventsAsync(
        Guid tenantId,
        int limit = 100,
        CancellationToken cancellationToken = default)
    {
        return await _context.AuditEvents
            .Where(e => e.TenantId == tenantId)
            .OrderByDescending(e => e.CreatedAt)
            .Take(limit)
            .Select(e => new AuditEventDto
            {
                Id = e.Id,
                TenantId = e.TenantId,
                EventType = e.EventType,
                UserId = e.UserId,
                Action = e.Action,
                DetailsJson = e.DetailsJson,
                PrevEventHash = e.PrevEventHash,
                EventHash = e.EventHash,
                CreatedAt = e.CreatedAt
            })
            .ToListAsync(cancellationToken);
    }

    public static string ComputeCanonicalPayload(
        Guid id,
        Guid tenantId,
        string eventType,
        Guid? userId,
        string action,
        string detailsJson,
        DateTime createdAt)
    {
        var utc = DateTime.SpecifyKind(createdAt, DateTimeKind.Utc);
        return $"{id:N}|{tenantId:N}|{eventType}|{userId?.ToString("N") ?? string.Empty}|{action}|{detailsJson}|{utc:yyyy-MM-ddTHH:mm:ss.ffffffZ}";
    }

    public static string ComputeHash(string prevHash, string canonicalPayload)
    {
        using var sha256 = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes($"{prevHash}:{canonicalPayload}");
        var hash = sha256.ComputeHash(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
