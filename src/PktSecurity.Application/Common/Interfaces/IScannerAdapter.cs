using PktSecurity.Application.DTOs;

namespace PktSecurity.Application.Common.Interfaces;

public record ScannerScanContext(
    Guid TenantId,
    Guid ProjectId,
    Guid ScanId,
    string TargetDirectory,
    string OutputFilePath);

public record ScannerExecutionResult(
    string ScannerName,
    bool Success,
    string? OutputSarifOrJsonFilePath,
    string? ErrorMessage,
    IReadOnlyList<NormalizedFindingDto> Findings);

public interface IScannerAdapter
{
    string ScannerName { get; }
    bool IsAvailable();
    Task<ScannerExecutionResult> ScanAsync(
        ScannerScanContext context,
        CancellationToken cancellationToken = default);
}
