using PktSecurity.Domain.Enums;

namespace PktSecurity.Application.DTOs;

public class ProjectDto
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public BusinessCriticality BusinessCriticality { get; set; }
    public bool IsInternetFacing { get; set; }
    public string DataSensitivity { get; set; } = "Internal";
    public DateTime CreatedAt { get; set; }
}

public class CreateProjectRequest
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public BusinessCriticality BusinessCriticality { get; set; } = BusinessCriticality.Medium;
    public bool IsInternetFacing { get; set; }
    public string DataSensitivity { get; set; } = "Internal";
    public string? RepositoryUrl { get; set; }
}

public class ScanDto
{
    public Guid Id { get; set; }
    public Guid ProjectId { get; set; }
    public ScanStatus Status { get; set; }
    public string TargetBranch { get; set; } = "main";
    public string? CommitHash { get; set; }
    public string? IdempotencyKey { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? CompletedAt { get; set; }
    public string? ErrorMessage { get; set; }
    public IReadOnlyList<ScanJobDto> Jobs { get; set; } = Array.Empty<ScanJobDto>();
}

public class ScanJobDto
{
    public Guid Id { get; set; }
    public Guid ScanId { get; set; }
    public string ScannerName { get; set; } = string.Empty;
    public ScanJobStatus Status { get; set; }
    public int AttemptCount { get; set; }
    public long? ExecutionDurationMs { get; set; }
    public string? ErrorMessage { get; set; }
    public DateTime CreatedAt { get; set; }
}

public class StartScanRequest
{
    public string? TargetBranch { get; set; } = "main";
    public string? CommitHash { get; set; }
    public string? TargetDirectory { get; set; }
    public IReadOnlyList<string>? Scanners { get; set; }
}
