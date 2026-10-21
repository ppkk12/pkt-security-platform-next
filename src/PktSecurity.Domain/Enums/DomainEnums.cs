namespace PktSecurity.Domain.Enums;

public enum UserRole
{
    SystemAdmin,
    TenantAdmin,
    SecurityEngineer,
    Developer,
    Auditor
}

public enum FindingSeverity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

public enum FindingStatus
{
    Open,
    InReview,
    Confirmed,
    FalsePositive,
    RiskAccepted,
    Remediated,
    Closed
}

public enum FindingCategory
{
    SAST,
    SCA,
    Secret,
    IaC,
    Container
}

public enum ScanStatus
{
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled
}

public enum ScanJobStatus
{
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled
}

public enum Reachability
{
    Unknown,
    NoPathFound,
    PotentiallyReachable,
    Reachable
}

public enum BusinessCriticality
{
    Low,
    Medium,
    High,
    Critical
}

public enum VexStatus
{
    NotAffected,
    Affected,
    Fixed,
    UnderInvestigation
}

public enum VexJustification
{
    ComponentNotPresent,
    VulnerableCodeNotPresent,
    VulnerableCodeNotInExecutePath,
    VulnerableCodeCannotBeControlledByAdversary,
    InlineMitigationsAlreadyExist
}

public enum RemediationVerificationStatus
{
    Pending,
    VerifiedFixed,
    PatchAppliesButFindingRemains,
    PatchInvalid
}

public enum RemediationApprovalStatus
{
    PendingReview,
    Approved,
    Rejected,
    Applied
}
