using PktSecurity.Application.DTOs;
using PktSecurity.Domain.Entities;

namespace PktSecurity.Application.Common.Interfaces;

public interface ISbomService
{
    Task<SbomDocumentSummaryDto> ImportCycloneDxAsync(
        Guid tenantId,
        Guid projectId,
        Stream stream,
        CancellationToken cancellationToken = default);

    Task<SbomRescanResultDto> RescanSbomAsync(
        Guid tenantId,
        Guid projectId,
        CancellationToken cancellationToken = default);

    Task<VexStatementDto> RegisterVexStatementAsync(
        Guid tenantId,
        Guid projectId,
        RegisterVexStatementRequest request,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<VexStatementDto>> GetVexStatementsAsync(
        Guid tenantId,
        Guid projectId,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ProjectDependencyDto>> GetProjectDependenciesAsync(
        Guid tenantId,
        Guid projectId,
        CancellationToken cancellationToken = default);
}
