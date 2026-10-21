using PktSecurity.Domain.Enums;

namespace PktSecurity.Application.DTOs;

public class SbomRescanResultDto
{
    public Guid ProjectId { get; set; }
    public int ScannedDependenciesCount { get; set; }
    public int VulnerabilitiesFoundCount { get; set; }
    public int SuppressedByVexCount { get; set; }
    public long DurationMs { get; set; }
    public IReadOnlyList<FindingSummaryDto> Findings { get; set; } = Array.Empty<FindingSummaryDto>();
}

public class RegisterVexStatementRequest
{
    public string VulnerabilityId { get; set; } = string.Empty;
    public string? PackagePurl { get; set; }
    public VexStatus Status { get; set; } = VexStatus.NotAffected;
    public VexJustification? Justification { get; set; }
    public string? ImpactStatement { get; set; }
    public string? ActionStatement { get; set; }
    public string? Author { get; set; }
}

public class VexStatementDto
{
    public Guid Id { get; set; }
    public Guid ProjectId { get; set; }
    public string VulnerabilityId { get; set; } = string.Empty;
    public string? PackagePurl { get; set; }
    public VexStatus Status { get; set; }
    public VexJustification? Justification { get; set; }
    public string? ImpactStatement { get; set; }
    public string? ActionStatement { get; set; }
    public string? Author { get; set; }
    public DateTime CreatedAt { get; set; }
}

public class SbomDocumentSummaryDto
{
    public Guid Id { get; set; }
    public Guid ProjectId { get; set; }
    public string Format { get; set; } = "CycloneDX";
    public string SpecVersion { get; set; } = "1.6";
    public string? SerialNumber { get; set; }
    public int Version { get; set; }
    public int ComponentCount { get; set; }
    public DateTime CreatedAt { get; set; }
}

public class ProjectDependencyDto
{
    public Guid Id { get; set; }
    public string PackagePurl { get; set; } = string.Empty;
    public string PackageName { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public bool IsDirect { get; set; }
    public int Depth { get; set; }
    public IReadOnlyList<string> DependencyPath { get; set; } = Array.Empty<string>();
}
