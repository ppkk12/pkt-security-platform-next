using PktSecurity.Application.DTOs;

namespace PktSecurity.Application.Common.Interfaces;

public interface IRemediationService
{
    Task<RemediationDto> GenerateRemediationAsync(
        Guid tenantId,
        Guid findingId,
        CancellationToken cancellationToken = default);

    Task<RemediationDto?> GetRemediationAsync(
        Guid tenantId,
        Guid findingId,
        CancellationToken cancellationToken = default);

    Task<RemediationVerificationResultDto> VerifyRemediationAsync(
        Guid tenantId,
        Guid remediationId,
        CancellationToken cancellationToken = default);

    Task<RemediationDto> ApproveRemediationAsync(
        Guid tenantId,
        Guid remediationId,
        Guid userId,
        CancellationToken cancellationToken = default);

    Task<RemediationDto> RejectRemediationAsync(
        Guid tenantId,
        Guid remediationId,
        Guid userId,
        string? reason,
        CancellationToken cancellationToken = default);
}
