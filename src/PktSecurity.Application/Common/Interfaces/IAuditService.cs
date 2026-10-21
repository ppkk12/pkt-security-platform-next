using PktSecurity.Application.DTOs;
using PktSecurity.Domain.Entities;

namespace PktSecurity.Application.Common.Interfaces;

public interface IAuditService
{
    Task<AuditEvent> RecordEventAsync(
        Guid tenantId,
        string eventType,
        Guid? userId,
        string action,
        object details,
        CancellationToken cancellationToken = default);

    Task<AuditVerificationResultDto> VerifyChainAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<AuditEventDto>> GetAuditEventsAsync(
        Guid tenantId,
        int limit = 100,
        CancellationToken cancellationToken = default);
}
