using System.Diagnostics;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using PktSecurity.Application.Common.Interfaces;
using PktSecurity.Application.DTOs;
using PktSecurity.Domain.Entities;
using PktSecurity.Domain.Enums;
using PktSecurity.Domain.Services;
using PktSecurity.Infrastructure.Data;
using PktSecurity.Infrastructure.Parsers;

namespace PktSecurity.Infrastructure.Services;

public class SbomService : ISbomService
{
    private readonly AppDbContext _context;
    private readonly CycloneDxStreamingParser _parser;
    private readonly ILogger<SbomService> _logger;

    public SbomService(
        AppDbContext context,
        CycloneDxStreamingParser parser,
        ILogger<SbomService> logger)
    {
        _context = context;
        _parser = parser;
        _logger = logger;
    }

    public async Task<SbomDocumentSummaryDto> ImportCycloneDxAsync(
        Guid tenantId,
        Guid projectId,
        Stream stream,
        CancellationToken cancellationToken = default)
    {
        var bom = await _parser.ParseAsync(stream, cancellationToken);

        var project = await _context.Projects
            .FirstOrDefaultAsync(p => p.Id == projectId, cancellationToken);

        if (project == null)
            throw new InvalidOperationException($"Project {projectId} not found");

        var sbomDoc = new SbomDocument
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            ProjectId = projectId,
            Format = "CycloneDX",
            SpecVersion = bom.SpecVersion,
            SerialNumber = bom.SerialNumber,
            Version = bom.Version,
            ComponentCount = bom.Components.Count,
            CreatedAt = DateTime.UtcNow
        };

        _context.SbomDocuments.Add(sbomDoc);

        // Build quick lookup for dependency parent-child relationships
        var dependencyGraph = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var dep in bom.Dependencies)
        {
            if (!dependencyGraph.ContainsKey(dep.Ref))
            {
                dependencyGraph[dep.Ref] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            }
            foreach (var d in dep.DependsOn)
            {
                dependencyGraph[dep.Ref].Add(d);
            }
        }

        var rootRef = bom.RootComponentRef ?? string.Empty;
        var directDependencies = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrEmpty(rootRef) && dependencyGraph.TryGetValue(rootRef, out var rootDeps))
        {
            directDependencies = rootDeps;
        }

        foreach (var comp in bom.Components)
        {
            // Upsert Package (global master)
            var package = await _context.Packages
                .FirstOrDefaultAsync(p => p.Purl == comp.Purl, cancellationToken);

            if (package == null)
            {
                var ecosystem = GetEcosystemFromPurl(comp.Purl);
                package = new Package
                {
                    Id = Guid.NewGuid(),
                    Purl = comp.Purl,
                    Name = comp.Name,
                    Version = comp.Version,
                    Ecosystem = ecosystem,
                    License = comp.License,
                    CreatedAt = DateTime.UtcNow
                };
                _context.Packages.Add(package);
            }

            // Determine if direct or transitive
            bool isDirect = true;
            int depth = 1;
            var path = new List<string> { project.Name, comp.Name };

            if (directDependencies.Count > 0)
            {
                var compRef = comp.BomRef ?? comp.Purl;
                if (!directDependencies.Contains(compRef))
                {
                    isDirect = false;
                    depth = 2;
                    path = new List<string> { project.Name, "dependencies", comp.Name };
                }
            }

            var projectDep = new ProjectDependency
            {
                Id = Guid.NewGuid(),
                TenantId = tenantId,
                ProjectId = projectId,
                SbomDocumentId = sbomDoc.Id,
                PackageId = package.Id,
                PackagePurl = comp.Purl,
                PackageName = comp.Name,
                Version = comp.Version,
                IsDirect = isDirect,
                Depth = depth,
                DependencyPathJson = JsonSerializer.Serialize(path),
                CreatedAt = DateTime.UtcNow
            };

            _context.ProjectDependencies.Add(projectDep);
        }

        await _context.SaveChangesAsync(cancellationToken);

        _logger.LogInformation("Imported CycloneDX SBOM for project {ProjectId} with {Count} components",
            projectId, bom.Components.Count);

        return new SbomDocumentSummaryDto
        {
            Id = sbomDoc.Id,
            ProjectId = projectId,
            Format = sbomDoc.Format,
            SpecVersion = sbomDoc.SpecVersion,
            SerialNumber = sbomDoc.SerialNumber,
            Version = sbomDoc.Version,
            ComponentCount = sbomDoc.ComponentCount,
            CreatedAt = sbomDoc.CreatedAt
        };
    }

    public async Task<SbomRescanResultDto> RescanSbomAsync(
        Guid tenantId,
        Guid projectId,
        CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();

        var project = await _context.Projects
            .FirstOrDefaultAsync(p => p.Id == projectId, cancellationToken);

        if (project == null)
            throw new InvalidOperationException($"Project {projectId} not found");

        var dependencies = await _context.ProjectDependencies
            .Where(d => d.ProjectId == projectId)
            .ToListAsync(cancellationToken);

        var vulnerabilities = await _context.Vulnerabilities
            .ToListAsync(cancellationToken);

        var vexStatements = await _context.VexStatements
            .Where(v => v.ProjectId == projectId)
            .ToListAsync(cancellationToken);

        var existingFindings = await _context.Findings
            .Where(f => f.ProjectId == projectId)
            .ToListAsync(cancellationToken);

        var existingByPrimary = existingFindings
            .ToDictionary(f => f.PrimaryFingerprint, StringComparer.OrdinalIgnoreCase);

        int vulnerabilitiesFoundCount = 0;
        int suppressedByVexCount = 0;
        var affectedFindings = new List<FindingSummaryDto>();

        foreach (var dep in dependencies)
        {
            foreach (var vuln in vulnerabilities)
            {
                if (IsVulnerable(dep.PackagePurl, dep.Version, vuln))
                {
                    // Check OpenVEX suppression
                    var matchingVex = vexStatements.FirstOrDefault(v =>
                        string.Equals(v.VulnerabilityId, vuln.CveId, StringComparison.OrdinalIgnoreCase) &&
                        (string.IsNullOrEmpty(v.PackagePurl) || string.Equals(v.PackagePurl, dep.PackagePurl, StringComparison.OrdinalIgnoreCase)));

                    bool isSuppressed = matchingVex != null && matchingVex.Status == VexStatus.NotAffected;

                    var primaryFp = FingerprintCalculator.ComputePrimary(
                        "sbom-matcher",
                        vuln.CveId,
                        dep.PackagePurl,
                        1);

                    var secondaryFp = FingerprintCalculator.ComputeSecondary(
                        tenantId,
                        projectId,
                        FindingCategory.SCA.ToString(),
                        vuln.CveId,
                        dep.PackagePurl,
                        dep.PackageName,
                        $"{dep.PackageName}@{dep.Version}");

                    var riskBreakdown = RiskScoreCalculator.Calculate(
                        vuln.Severity,
                        vuln.IsKev,
                        vuln.EpssScore,
                        Reachability.PotentiallyReachable,
                        project.BusinessCriticality,
                        project.IsInternetFacing,
                        vuln.CvssScore);

                    if (isSuppressed)
                    {
                        suppressedByVexCount++;

                        if (existingByPrimary.TryGetValue(primaryFp, out var existingF))
                        {
                            if (existingF.Status != FindingStatus.RiskAccepted)
                            {
                                _context.FindingStatusHistories.Add(new FindingStatusHistory
                                {
                                    Id = Guid.NewGuid(),
                                    TenantId = tenantId,
                                    FindingId = existingF.Id,
                                    FromStatus = existingF.Status,
                                    ToStatus = FindingStatus.RiskAccepted,
                                    Reason = $"OpenVEX not_affected: {matchingVex?.Justification} - {matchingVex?.ImpactStatement}",
                                    CreatedAt = DateTime.UtcNow
                                });
                                existingF.Status = FindingStatus.RiskAccepted;
                                existingF.UpdatedAt = DateTime.UtcNow;
                            }
                        }
                        continue;
                    }

                    vulnerabilitiesFoundCount++;

                    if (existingByPrimary.TryGetValue(primaryFp, out var existing))
                    {
                        existing.OccurrenceCount++;
                        existing.RiskScore = riskBreakdown.FinalScore;
                        existing.UpdatedAt = DateTime.UtcNow;

                        _context.RiskAssessments.Add(new RiskAssessment
                        {
                            Id = Guid.NewGuid(),
                            TenantId = tenantId,
                            FindingId = existing.Id,
                            FinalScore = riskBreakdown.FinalScore,
                            BaseSeverityScore = riskBreakdown.BaseSeverityScore,
                            ThreatScore = riskBreakdown.ThreatScore,
                            ReachabilityScore = riskBreakdown.ReachabilityScore,
                            AssetMultiplier = riskBreakdown.AssetMultiplier,
                            FormulaVersion = "1.0",
                            CvssScore = vuln.CvssScore,
                            IsKev = vuln.IsKev,
                            EpssScore = vuln.EpssScore,
                            Reachability = Reachability.PotentiallyReachable,
                            MissingInputsJson = JsonSerializer.Serialize(riskBreakdown.MissingInputs),
                            CalculatedAt = DateTime.UtcNow
                        });

                        affectedFindings.Add(MapToSummary(existing));
                    }
                    else
                    {
                        var newFinding = new Finding
                        {
                            Id = Guid.NewGuid(),
                            TenantId = tenantId,
                            ProjectId = projectId,
                            Title = $"{vuln.CveId}: {vuln.Summary}",
                            Description = vuln.Description,
                            Severity = vuln.Severity,
                            RiskScore = riskBreakdown.FinalScore,
                            Confidence = 1.0,
                            Status = FindingStatus.Open,
                            Category = FindingCategory.SCA,
                            ScannerName = "sbom-matcher",
                            CveId = vuln.CveId,
                            CweId = vuln.CweId,
                            PackagePurl = dep.PackagePurl,
                            InstalledVersion = dep.Version,
                            FixedVersion = vuln.FixedVersion,
                            FilePath = dep.PackagePurl,
                            StartLine = 1,
                            EndLine = 1,
                            IsKev = vuln.IsKev,
                            EpssScore = vuln.EpssScore,
                            Reachability = Reachability.PotentiallyReachable,
                            PrimaryFingerprint = primaryFp,
                            SecondaryFingerprint = secondaryFp,
                            OccurrenceCount = 1,
                            FirstSeenScanId = Guid.Empty,
                            LastSeenScanId = Guid.Empty,
                            CreatedAt = DateTime.UtcNow,
                            UpdatedAt = DateTime.UtcNow
                        };

                        var evidence = new FindingEvidence
                        {
                            Id = Guid.NewGuid(),
                            TenantId = tenantId,
                            FindingId = newFinding.Id,
                            CodeSnippetRedacted = $"Dependency: {dep.PackageName}@{dep.Version}",
                            CreatedAt = DateTime.UtcNow
                        };

                        newFinding.Evidences.Add(evidence);
                        _context.Findings.Add(newFinding);

                        _context.RiskAssessments.Add(new RiskAssessment
                        {
                            Id = Guid.NewGuid(),
                            TenantId = tenantId,
                            FindingId = newFinding.Id,
                            FinalScore = riskBreakdown.FinalScore,
                            BaseSeverityScore = riskBreakdown.BaseSeverityScore,
                            ThreatScore = riskBreakdown.ThreatScore,
                            ReachabilityScore = riskBreakdown.ReachabilityScore,
                            AssetMultiplier = riskBreakdown.AssetMultiplier,
                            FormulaVersion = "1.0",
                            CvssScore = vuln.CvssScore,
                            IsKev = vuln.IsKev,
                            EpssScore = vuln.EpssScore,
                            Reachability = Reachability.PotentiallyReachable,
                            MissingInputsJson = JsonSerializer.Serialize(riskBreakdown.MissingInputs),
                            CalculatedAt = DateTime.UtcNow
                        });

                        existingByPrimary[primaryFp] = newFinding;
                        affectedFindings.Add(MapToSummary(newFinding));
                    }
                }
            }
        }

        await _context.SaveChangesAsync(cancellationToken);
        stopwatch.Stop();

        _logger.LogInformation("Fast SBOM rescan for project {ProjectId} completed in {Elapsed}ms. Scanned {DepCount} dependencies, found {VulnCount} vulnerabilities, suppressed {VexCount} via OpenVEX",
            projectId, stopwatch.ElapsedMilliseconds, dependencies.Count, vulnerabilitiesFoundCount, suppressedByVexCount);

        return new SbomRescanResultDto
        {
            ProjectId = projectId,
            ScannedDependenciesCount = dependencies.Count,
            VulnerabilitiesFoundCount = vulnerabilitiesFoundCount,
            SuppressedByVexCount = suppressedByVexCount,
            DurationMs = stopwatch.ElapsedMilliseconds,
            Findings = affectedFindings
        };
    }

    public async Task<VexStatementDto> RegisterVexStatementAsync(
        Guid tenantId,
        Guid projectId,
        RegisterVexStatementRequest request,
        CancellationToken cancellationToken = default)
    {
        var statement = new VexStatement
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            ProjectId = projectId,
            VulnerabilityId = request.VulnerabilityId,
            PackagePurl = request.PackagePurl,
            Status = request.Status,
            Justification = request.Justification,
            ImpactStatement = request.ImpactStatement,
            ActionStatement = request.ActionStatement,
            Author = request.Author,
            CreatedAt = DateTime.UtcNow
        };

        _context.VexStatements.Add(statement);

        // If statement is NotAffected, transition any matching findings to RiskAccepted
        if (request.Status == VexStatus.NotAffected)
        {
            var matchingFindings = await _context.Findings
                .Where(f => f.ProjectId == projectId && f.CveId == request.VulnerabilityId)
                .ToListAsync(cancellationToken);

            foreach (var finding in matchingFindings)
            {
                if (!string.IsNullOrEmpty(request.PackagePurl) &&
                    !string.Equals(finding.PackagePurl, request.PackagePurl, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (finding.Status != FindingStatus.RiskAccepted)
                {
                    _context.FindingStatusHistories.Add(new FindingStatusHistory
                    {
                        Id = Guid.NewGuid(),
                        TenantId = tenantId,
                        FindingId = finding.Id,
                        FromStatus = finding.Status,
                        ToStatus = FindingStatus.RiskAccepted,
                        Reason = $"OpenVEX not_affected: {request.Justification} - {request.ImpactStatement}",
                        CreatedAt = DateTime.UtcNow
                    });

                    finding.Status = FindingStatus.RiskAccepted;
                    finding.UpdatedAt = DateTime.UtcNow;
                }
            }
        }

        await _context.SaveChangesAsync(cancellationToken);

        _logger.LogInformation("Registered OpenVEX statement {Id} ({Status}) for project {ProjectId}, vulnerability {VulnId}",
            statement.Id, statement.Status, projectId, statement.VulnerabilityId);

        return new VexStatementDto
        {
            Id = statement.Id,
            ProjectId = projectId,
            VulnerabilityId = statement.VulnerabilityId,
            PackagePurl = statement.PackagePurl,
            Status = statement.Status,
            Justification = statement.Justification,
            ImpactStatement = statement.ImpactStatement,
            ActionStatement = statement.ActionStatement,
            Author = statement.Author,
            CreatedAt = statement.CreatedAt
        };
    }

    public async Task<IReadOnlyList<VexStatementDto>> GetVexStatementsAsync(
        Guid tenantId,
        Guid projectId,
        CancellationToken cancellationToken = default)
    {
        return await _context.VexStatements
            .AsNoTracking()
            .Where(v => v.ProjectId == projectId)
            .OrderByDescending(v => v.CreatedAt)
            .Select(v => new VexStatementDto
            {
                Id = v.Id,
                ProjectId = v.ProjectId,
                VulnerabilityId = v.VulnerabilityId,
                PackagePurl = v.PackagePurl,
                Status = v.Status,
                Justification = v.Justification,
                ImpactStatement = v.ImpactStatement,
                ActionStatement = v.ActionStatement,
                Author = v.Author,
                CreatedAt = v.CreatedAt
            })
            .ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<ProjectDependencyDto>> GetProjectDependenciesAsync(
        Guid tenantId,
        Guid projectId,
        CancellationToken cancellationToken = default)
    {
        var deps = await _context.ProjectDependencies
            .AsNoTracking()
            .Where(d => d.ProjectId == projectId)
            .OrderBy(d => d.PackageName)
            .ToListAsync(cancellationToken);

        return deps.Select(d => new ProjectDependencyDto
        {
            Id = d.Id,
            PackagePurl = d.PackagePurl,
            PackageName = d.PackageName,
            Version = d.Version,
            IsDirect = d.IsDirect,
            Depth = d.Depth,
            DependencyPath = JsonSerializer.Deserialize<List<string>>(d.DependencyPathJson) ?? new List<string>()
        }).ToList();
    }

    private static bool IsVulnerable(string purl, string version, Vulnerability vuln)
    {
        if (string.IsNullOrWhiteSpace(vuln.AffectedPurlPattern))
            return false;

        // Match PURL prefix, e.g. "pkg:npm/lodash" in "pkg:npm/lodash@4.17.20"
        if (!purl.StartsWith(vuln.AffectedPurlPattern, StringComparison.OrdinalIgnoreCase))
            return false;

        // Simple version comparison support, e.g. "<4.17.21"
        if (vuln.AffectedVersionRange.StartsWith("<") && !string.IsNullOrWhiteSpace(vuln.FixedVersion))
        {
            return CompareVersions(version, vuln.FixedVersion) < 0;
        }

        return true;
    }

    private static int CompareVersions(string v1, string v2)
    {
        if (Version.TryParse(v1, out var ver1) && Version.TryParse(v2, out var ver2))
        {
            return ver1.CompareTo(ver2);
        }
        return string.Compare(v1, v2, StringComparison.OrdinalIgnoreCase);
    }

    private static string GetEcosystemFromPurl(string purl)
    {
        if (purl.StartsWith("pkg:npm/", StringComparison.OrdinalIgnoreCase)) return "npm";
        if (purl.StartsWith("pkg:pypi/", StringComparison.OrdinalIgnoreCase)) return "pypi";
        if (purl.StartsWith("pkg:nuget/", StringComparison.OrdinalIgnoreCase)) return "nuget";
        if (purl.StartsWith("pkg:golang/", StringComparison.OrdinalIgnoreCase)) return "golang";
        if (purl.StartsWith("pkg:maven/", StringComparison.OrdinalIgnoreCase)) return "maven";
        return "generic";
    }

    private static FindingSummaryDto MapToSummary(Finding f) => new()
    {
        Id = f.Id,
        ProjectId = f.ProjectId,
        Title = f.Title,
        Severity = f.Severity,
        RiskScore = f.RiskScore,
        Status = f.Status,
        Category = f.Category,
        ScannerName = f.ScannerName,
        CweId = f.CweId,
        CveId = f.CveId,
        FilePath = f.FilePath,
        StartLine = f.StartLine,
        IsKev = f.IsKev,
        EpssScore = f.EpssScore,
        OccurrenceCount = f.OccurrenceCount,
        CreatedAt = f.CreatedAt,
        UpdatedAt = f.UpdatedAt
    };
}
