using PktSecurity.Domain.Common;
using PktSecurity.Domain.Enums;

namespace PktSecurity.Domain.Entities;

public class Organization : IAuditable
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public ICollection<Tenant> Tenants { get; set; } = new List<Tenant>();
}

public class Tenant : IAuditable
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid OrganizationId { get; set; }
    public string Name { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public Organization? Organization { get; set; }
    public ICollection<User> Users { get; set; } = new List<User>();
    public ICollection<Project> Projects { get; set; } = new List<Project>();
}

public class User : ITenantScoped, IAuditable
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid TenantId { get; set; }
    public string Email { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public UserRole Role { get; set; } = UserRole.Developer;
    public string PasswordHash { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public Tenant? Tenant { get; set; }
}

public class ApiKey : ITenantScoped, IAuditable
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid TenantId { get; set; }
    public string Name { get; set; } = string.Empty;
    public string KeyHash { get; set; } = string.Empty;
    public string Prefix { get; set; } = string.Empty;
    public UserRole Role { get; set; } = UserRole.Developer;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? ExpiresAt { get; set; }
    public bool IsRevoked { get; set; }

    public Tenant? Tenant { get; set; }
}

public class Project : ITenantScoped, IAuditable
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid TenantId { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public BusinessCriticality BusinessCriticality { get; set; } = BusinessCriticality.Medium;
    public bool IsInternetFacing { get; set; }
    public string DataSensitivity { get; set; } = "Internal";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public Tenant? Tenant { get; set; }
    public ICollection<Repository> Repositories { get; set; } = new List<Repository>();
    public ICollection<Scan> Scans { get; set; } = new List<Scan>();
    public ICollection<Finding> Findings { get; set; } = new List<Finding>();
    public ICollection<SbomDocument> SbomDocuments { get; set; } = new List<SbomDocument>();
    public ICollection<ProjectDependency> Dependencies { get; set; } = new List<ProjectDependency>();
    public ICollection<VexStatement> VexStatements { get; set; } = new List<VexStatement>();
}

public class Repository : ITenantScoped, IAuditable
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid TenantId { get; set; }
    public Guid ProjectId { get; set; }
    public string RepoUrl { get; set; } = string.Empty;
    public string DefaultBranch { get; set; } = "main";
    public string? EncryptedCredential { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public Project? Project { get; set; }
}

public class Scan : ITenantScoped, IAuditable
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid TenantId { get; set; }
    public Guid ProjectId { get; set; }
    public ScanStatus Status { get; set; } = ScanStatus.Queued;
    public string TargetBranch { get; set; } = "main";
    public string? CommitHash { get; set; }
    public string? IdempotencyKey { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? CompletedAt { get; set; }
    public string? ErrorMessage { get; set; }

    public Project? Project { get; set; }
    public ICollection<ScanJob> Jobs { get; set; } = new List<ScanJob>();
}

public class ScanJob : ITenantScoped, IAuditable
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid TenantId { get; set; }
    public Guid ScanId { get; set; }
    public string ScannerName { get; set; } = string.Empty;
    public ScanJobStatus Status { get; set; } = ScanJobStatus.Queued;
    public int Priority { get; set; } = 100;
    public string? LeaseOwner { get; set; }
    public DateTime? LeasedUntil { get; set; }
    public DateTime? HeartbeatAt { get; set; }
    public int AttemptCount { get; set; }
    public int MaxAttempts { get; set; } = 3;
    public bool CancelRequested { get; set; }
    public long? ExecutionDurationMs { get; set; }
    public string? ErrorMessage { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? StartedAt { get; set; }
    public DateTime? CompletedAt { get; set; }

    public Scan? Scan { get; set; }
}

public class Finding : ITenantScoped, IAuditable
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid TenantId { get; set; }
    public Guid ProjectId { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public FindingSeverity Severity { get; set; } = FindingSeverity.Medium;
    public double RiskScore { get; set; }
    public double Confidence { get; set; } = 1.0;
    public FindingStatus Status { get; set; } = FindingStatus.Open;
    public FindingCategory Category { get; set; } = FindingCategory.SAST;
    public string ScannerName { get; set; } = string.Empty;
    public string? CweId { get; set; }
    public string? CveId { get; set; }
    public string? PackagePurl { get; set; }
    public string? InstalledVersion { get; set; }
    public string? FixedVersion { get; set; }
    public string? FilePath { get; set; }
    public int? StartLine { get; set; }
    public int? EndLine { get; set; }
    public string? EnclosingSymbol { get; set; }
    public bool IsKev { get; set; }
    public double? EpssScore { get; set; }
    public Reachability Reachability { get; set; } = Reachability.Unknown;
    public string PrimaryFingerprint { get; set; } = string.Empty;
    public string SecondaryFingerprint { get; set; } = string.Empty;
    public Guid? CorrelationGroupId { get; set; }
    public int OccurrenceCount { get; set; } = 1;
    public Guid FirstSeenScanId { get; set; }
    public Guid LastSeenScanId { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    public Project? Project { get; set; }
    public ICollection<FindingEvidence> Evidences { get; set; } = new List<FindingEvidence>();
    public ICollection<FindingStatusHistory> StatusHistory { get; set; } = new List<FindingStatusHistory>();
    public ICollection<RiskAssessment> RiskAssessments { get; set; } = new List<RiskAssessment>();
    public ICollection<Remediation> Remediations { get; set; } = new List<Remediation>();
}

public class FindingEvidence : ITenantScoped, IAuditable
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid TenantId { get; set; }
    public Guid FindingId { get; set; }
    public string? CodeSnippetRedacted { get; set; }
    public string? CodeFlowJson { get; set; }
    public string? RawSarifResultJson { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public Finding? Finding { get; set; }
}

public class FindingStatusHistory : ITenantScoped, IAuditable
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid TenantId { get; set; }
    public Guid FindingId { get; set; }
    public FindingStatus FromStatus { get; set; }
    public FindingStatus ToStatus { get; set; }
    public Guid? ChangedByUserId { get; set; }
    public string? Reason { get; set; }
    public Guid? ApprovedByUserId { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public Finding? Finding { get; set; }
}

public class AuditEvent : ITenantScoped, IAuditable
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid TenantId { get; set; }
    public string EventType { get; set; } = string.Empty;
    public Guid? UserId { get; set; }
    public string Action { get; set; } = string.Empty;
    public string DetailsJson { get; set; } = "{}";
    public string PrevEventHash { get; set; } = string.Empty;
    public string EventHash { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

public class RiskAssessment : ITenantScoped, IAuditable
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid TenantId { get; set; }
    public Guid FindingId { get; set; }
    public double FinalScore { get; set; }
    public double BaseSeverityScore { get; set; }
    public double ThreatScore { get; set; }
    public double ReachabilityScore { get; set; }
    public double AssetMultiplier { get; set; }
    public string FormulaVersion { get; set; } = "1.0";
    public double? CvssScore { get; set; }
    public bool? IsKev { get; set; }
    public double? EpssScore { get; set; }
    public Reachability Reachability { get; set; } = Reachability.Unknown;
    public string MissingInputsJson { get; set; } = "[]";
    public DateTime CalculatedAt { get; set; } = DateTime.UtcNow;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public Finding? Finding { get; set; }
}

public class Package : IAuditable
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Purl { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string Ecosystem { get; set; } = string.Empty;
    public string? License { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public ICollection<ProjectDependency> Dependencies { get; set; } = new List<ProjectDependency>();
}

public class Vulnerability : IAuditable
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string CveId { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public FindingSeverity Severity { get; set; } = FindingSeverity.Medium;
    public double? CvssScore { get; set; }
    public string? CweId { get; set; }
    public string AffectedPurlPattern { get; set; } = string.Empty;
    public string AffectedVersionRange { get; set; } = string.Empty;
    public string? FixedVersion { get; set; }
    public bool IsKev { get; set; }
    public double? EpssScore { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

public class SbomDocument : ITenantScoped, IAuditable
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid TenantId { get; set; }
    public Guid ProjectId { get; set; }
    public string Format { get; set; } = "CycloneDX";
    public string SpecVersion { get; set; } = "1.6";
    public string? SerialNumber { get; set; }
    public int Version { get; set; } = 1;
    public int ComponentCount { get; set; }
    public string? RawJson { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public Project? Project { get; set; }
    public ICollection<ProjectDependency> Dependencies { get; set; } = new List<ProjectDependency>();
}

public class ProjectDependency : ITenantScoped, IAuditable
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid TenantId { get; set; }
    public Guid ProjectId { get; set; }
    public Guid SbomDocumentId { get; set; }
    public Guid PackageId { get; set; }
    public string PackagePurl { get; set; } = string.Empty;
    public string PackageName { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public bool IsDirect { get; set; } = true;
    public int Depth { get; set; } = 1;
    public string DependencyPathJson { get; set; } = "[]";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public Project? Project { get; set; }
    public SbomDocument? SbomDocument { get; set; }
    public Package? Package { get; set; }
}

public class VexStatement : ITenantScoped, IAuditable
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid TenantId { get; set; }
    public Guid ProjectId { get; set; }
    public string VulnerabilityId { get; set; } = string.Empty;
    public string? PackagePurl { get; set; }
    public VexStatus Status { get; set; } = VexStatus.NotAffected;
    public VexJustification? Justification { get; set; }
    public string? ImpactStatement { get; set; }
    public string? ActionStatement { get; set; }
    public string? Author { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public Project? Project { get; set; }
}

public class Remediation : ITenantScoped, IAuditable
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid TenantId { get; set; }
    public Guid FindingId { get; set; }
    public string VerifiedFactsJson { get; set; } = "[]";
    public string AiHypothesisAnalysis { get; set; } = string.Empty;
    public string ProposedUnifiedDiff { get; set; } = string.Empty;
    public string SideEffectsWarning { get; set; } = string.Empty;
    public RemediationVerificationStatus VerificationStatus { get; set; } = RemediationVerificationStatus.Pending;
    public string? VerificationDetails { get; set; }
    public RemediationApprovalStatus ApprovalStatus { get; set; } = RemediationApprovalStatus.PendingReview;
    public Guid? ApprovedByUserId { get; set; }
    public DateTime? ApprovedAt { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    public Finding? Finding { get; set; }
}
