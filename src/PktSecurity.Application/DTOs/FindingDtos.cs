using PktSecurity.Domain.Enums;

namespace PktSecurity.Application.DTOs;

public class NormalizedFindingDto
{
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public FindingSeverity Severity { get; set; } = FindingSeverity.Medium;
    public FindingCategory Category { get; set; } = FindingCategory.SAST;
    public string ScannerName { get; set; } = string.Empty;
    public string? RuleId { get; set; }
    public string? CweId { get; set; }
    public string? CveId { get; set; }
    public string? PackagePurl { get; set; }
    public string? InstalledVersion { get; set; }
    public string? FixedVersion { get; set; }
    public string? FilePath { get; set; }
    public int? StartLine { get; set; }
    public int? EndLine { get; set; }
    public string? EnclosingSymbol { get; set; }
    public string? CodeSnippet { get; set; }
    public string? RawResultJson { get; set; }
    public bool IsKev { get; set; }
    public double? EpssScore { get; set; }
    public Reachability Reachability { get; set; } = Reachability.Unknown;
}

public class FindingSummaryDto
{
    public Guid Id { get; set; }
    public Guid ProjectId { get; set; }
    public string Title { get; set; } = string.Empty;
    public FindingSeverity Severity { get; set; }
    public double RiskScore { get; set; }
    public FindingStatus Status { get; set; }
    public FindingCategory Category { get; set; }
    public string ScannerName { get; set; } = string.Empty;
    public string? CweId { get; set; }
    public string? CveId { get; set; }
    public string? FilePath { get; set; }
    public int? StartLine { get; set; }
    public bool IsKev { get; set; }
    public double? EpssScore { get; set; }
    public int OccurrenceCount { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public class FindingEvidenceDto
{
    public Guid Id { get; set; }
    public string? CodeSnippetRedacted { get; set; }
    public string? CodeFlowJson { get; set; }
    public string? RawSarifResultJson { get; set; }
    public DateTime CreatedAt { get; set; }
}

public class FindingStatusHistoryDto
{
    public Guid Id { get; set; }
    public FindingStatus FromStatus { get; set; }
    public FindingStatus ToStatus { get; set; }
    public Guid? ChangedByUserId { get; set; }
    public string? Reason { get; set; }
    public Guid? ApprovedByUserId { get; set; }
    public DateTime CreatedAt { get; set; }
}

public class FindingDetailDto : FindingSummaryDto
{
    public string Description { get; set; } = string.Empty;
    public double Confidence { get; set; }
    public string? PackagePurl { get; set; }
    public string? InstalledVersion { get; set; }
    public string? FixedVersion { get; set; }
    public int? EndLine { get; set; }
    public string? EnclosingSymbol { get; set; }
    public Reachability Reachability { get; set; }
    public Guid? CorrelationGroupId { get; set; }
    public string PrimaryFingerprint { get; set; } = string.Empty;
    public string SecondaryFingerprint { get; set; } = string.Empty;
    public RiskAssessmentDto? LatestRiskAssessment { get; set; }
    public IReadOnlyList<FindingEvidenceDto> Evidences { get; set; } = Array.Empty<FindingEvidenceDto>();
    public IReadOnlyList<FindingStatusHistoryDto> StatusHistory { get; set; } = Array.Empty<FindingStatusHistoryDto>();
}

public class RiskAssessmentDto
{
    public Guid Id { get; set; }
    public double FinalScore { get; set; }
    public double BaseSeverityScore { get; set; }
    public double ThreatScore { get; set; }
    public double ReachabilityScore { get; set; }
    public double AssetMultiplier { get; set; }
    public string FormulaVersion { get; set; } = "1.0";
    public double? CvssScore { get; set; }
    public bool? IsKev { get; set; }
    public double? EpssScore { get; set; }
    public Reachability Reachability { get; set; }
    public IReadOnlyList<string> MissingInputs { get; set; } = Array.Empty<string>();
    public DateTime CalculatedAt { get; set; }
}

public class FindingSearchQuery
{
    public Guid? ProjectId { get; set; }
    public FindingSeverity? Severity { get; set; }
    public FindingStatus? Status { get; set; }
    public FindingCategory? Category { get; set; }
    public bool? IsKev { get; set; }
    public string? Keyword { get; set; }
    public string? Cursor { get; set; }
    public int? Limit { get; set; } = 50;
}

public class PagedResult<T>
{
    public IReadOnlyList<T> Items { get; set; } = Array.Empty<T>();
    public string? NextCursor { get; set; }
    public bool HasMore { get; set; }
    public int TotalCount { get; set; }
}
