using PktSecurity.Application.DTOs;

namespace PktSecurity.Application.Common.Interfaces;

public interface IFindingSearchService
{
    Task<PagedResult<FindingSummaryDto>> SearchFindingsAsync(
        FindingSearchQuery query,
        CancellationToken cancellationToken = default);

    Task<FindingDetailDto?> GetFindingDetailAsync(
        Guid findingId,
        CancellationToken cancellationToken = default);
}

public interface IExportService
{
    Task<byte[]> ExportProjectFindingsAsync(
        Guid projectId,
        string format, // "json", "csv", "sarif"
        CancellationToken cancellationToken = default);
}
