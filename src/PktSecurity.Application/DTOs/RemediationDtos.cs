using PktSecurity.Domain.Enums;

namespace PktSecurity.Application.DTOs;

public class RemediationDto
{
    public Guid Id { get; set; }
    public Guid FindingId { get; set; }
    public IReadOnlyList<string> VerifiedFacts { get; set; } = Array.Empty<string>();
    public string AiHypothesisAnalysis { get; set; } = string.Empty;
    public string ProposedUnifiedDiff { get; set; } = string.Empty;
    public string SideEffectsWarning { get; set; } = string.Empty;
    public RemediationVerificationStatus VerificationStatus { get; set; }
    public string? VerificationDetails { get; set; }
    public RemediationApprovalStatus ApprovalStatus { get; set; }
    public Guid? ApprovedByUserId { get; set; }
    public DateTime? ApprovedAt { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public class RemediationVerificationResultDto
{
    public Guid RemediationId { get; set; }
    public RemediationVerificationStatus VerificationStatus { get; set; }
    public string Details { get; set; } = string.Empty;
    public long DurationMs { get; set; }
}

public class ApproveRemediationRequest
{
    public string? Reason { get; set; }
}

public class RejectRemediationRequest
{
    public string Reason { get; set; } = string.Empty;
}

public class RemediationSuggestion
{
    public List<string> VerifiedFacts { get; set; } = new();
    public string AiHypothesisAnalysis { get; set; } = string.Empty;
    public string ProposedUnifiedDiff { get; set; } = string.Empty;
    public string SideEffectsWarning { get; set; } = string.Empty;
}

public class RemediationContext
{
    public Guid FindingId { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public FindingCategory Category { get; set; }
    public string ScannerName { get; set; } = string.Empty;
    public string? CweId { get; set; }
    public string? CveId { get; set; }
    public string? PackagePurl { get; set; }
    public string? InstalledVersion { get; set; }
    public string? FixedVersion { get; set; }
    public string? FilePath { get; set; }
    public int? StartLine { get; set; }
    public int? EndLine { get; set; }
    public string? CodeSnippet { get; set; }
    public string? FullFileContent { get; set; }
    public string? EnclosingSymbol { get; set; }
}

public class AuditVerificationResultDto
{
    public bool IsValid { get; set; }
    public int TotalEvents { get; set; }
    public Guid? BrokenEventId { get; set; }
    public string? BrokenReason { get; set; }
}

public class AuditEventDto
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public string EventType { get; set; } = string.Empty;
    public Guid? UserId { get; set; }
    public string Action { get; set; } = string.Empty;
    public string DetailsJson { get; set; } = "{}";
    public string PrevEventHash { get; set; } = string.Empty;
    public string EventHash { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
}
