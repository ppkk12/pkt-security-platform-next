using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using PktSecurity.Application.Common.Interfaces;
using PktSecurity.Domain.Enums;
using PktSecurity.Infrastructure.Data;

namespace PktSecurity.Infrastructure.Services;

public class ExportService : IExportService
{
    private readonly AppDbContext _context;

    public ExportService(AppDbContext context)
    {
        _context = context;
    }

    public async Task<byte[]> ExportProjectFindingsAsync(
        Guid projectId,
        string format,
        CancellationToken cancellationToken = default)
    {
        var findings = await _context.Findings
            .AsNoTracking()
            .Where(f => f.ProjectId == projectId)
            .OrderByDescending(f => f.RiskScore)
            .ToListAsync(cancellationToken);

        var fmt = (format ?? "json").Trim().ToLowerInvariant();

        switch (fmt)
        {
            case "csv":
                return ExportCsv(findings);
            case "sarif":
                return ExportSarif(findings);
            case "cyclonedx":
                return await ExportCycloneDxAsync(projectId, findings, cancellationToken);
            case "meti":
            case "meti-audit":
            case "audit-report":
                return await ExportMetiAuditReportAsync(projectId, findings, cancellationToken);
            case "json":
            default:
                return ExportJson(findings);
        }
    }

    private async Task<byte[]> ExportCycloneDxAsync(
        Guid projectId,
        IReadOnlyList<Domain.Entities.Finding> findings,
        CancellationToken cancellationToken)
    {
        var project = await _context.Projects.AsNoTracking().FirstOrDefaultAsync(p => p.Id == projectId, cancellationToken);
        var dependencies = await _context.ProjectDependencies
            .AsNoTracking()
            .Where(d => d.ProjectId == projectId)
            .ToListAsync(cancellationToken);

        var bom = new
        {
            bomFormat = "CycloneDX",
            specVersion = "1.5",
            serialNumber = $"urn:uuid:{Guid.NewGuid()}",
            version = 1,
            metadata = new
            {
                timestamp = DateTime.UtcNow.ToString("O"),
                component = new
                {
                    name = project?.Name ?? "Unknown Project",
                    type = "application",
                    version = "1.0.0"
                }
            },
            components = dependencies.Select(d => new
            {
                type = "library",
                name = d.PackageName,
                version = d.Version,
                purl = d.PackagePurl
            }).ToArray(),
            vulnerabilities = findings.Where(f => !string.IsNullOrEmpty(f.CveId)).Select(f => new
            {
                id = f.CveId,
                ratings = new[]
                {
                    new
                    {
                        severity = f.Severity.ToString().ToLowerInvariant(),
                        score = f.RiskScore,
                        method = "CVSSv31"
                    }
                },
                description = f.Title,
                affects = new[]
                {
                    new { @ref = f.PackagePurl ?? f.FilePath ?? "project" }
                }
            }).ToArray()
        };

        var json = JsonSerializer.Serialize(bom, new JsonSerializerOptions { WriteIndented = true });
        return Encoding.UTF8.GetBytes(json);
    }

    private async Task<byte[]> ExportMetiAuditReportAsync(
        Guid projectId,
        IReadOnlyList<Domain.Entities.Finding> findings,
        CancellationToken cancellationToken)
    {
        var project = await _context.Projects.AsNoTracking().FirstOrDefaultAsync(p => p.Id == projectId, cancellationToken);
        var dependencies = await _context.ProjectDependencies
            .AsNoTracking()
            .Where(d => d.ProjectId == projectId)
            .ToListAsync(cancellationToken);

        var vexStatements = await _context.VexStatements
            .AsNoTracking()
            .Where(v => v.ProjectId == projectId)
            .ToListAsync(cancellationToken);

        var report = new
        {
            reportTitle = "経済産業省「ソフトウェア管理に向けたSBOMの導入に関する手引書」対応 ソフトウェア脆弱性監査報告書",
            standard = "METI Software Bill of Materials (SBOM) Implementation Guidelines Ver 1.0",
            generatedAt = DateTime.UtcNow.ToString("yyyy年MM月dd日 HH:mm:ss (UTC)"),
            targetSoftware = new
            {
                projectId = project?.Id ?? projectId,
                name = project?.Name ?? "不明なプロジェクト",
                description = project?.Description ?? string.Empty,
                businessCriticality = project?.BusinessCriticality.ToString() ?? "Medium",
                isInternetFacing = project?.IsInternetFacing ?? false,
                dataSensitivity = project?.DataSensitivity ?? "Internal"
            },
            complianceSummary = new
            {
                totalComponents = dependencies.Count,
                directDependenciesCount = dependencies.Count(d => d.IsDirect),
                transitiveDependenciesCount = dependencies.Count(d => !d.IsDirect),
                totalIdentifiedVulnerabilities = findings.Count,
                criticalVulnerabilities = findings.Count(f => f.Severity == FindingSeverity.Critical),
                highVulnerabilities = findings.Count(f => f.Severity == FindingSeverity.High),
                cisaKevVulnerabilities = findings.Count(f => f.IsKev),
                openVexSuppressedCount = vexStatements.Count,
                remediatedCount = findings.Count(f => f.Status == FindingStatus.Remediated),
                riskAcceptedCount = findings.Count(f => f.Status == FindingStatus.RiskAccepted)
            },
            componentInventory = dependencies.Select(d => new
            {
                packageName = d.PackageName,
                version = d.Version,
                purl = d.PackagePurl,
                dependencyType = d.IsDirect ? "直接依存" : "間接依存"
            }),
            vulnerabilityTriageList = findings.Select(f =>
            {
                var vex = vexStatements.FirstOrDefault(v => v.VulnerabilityId == f.CveId);
                return new
                {
                    cveId = f.CveId ?? f.CweId ?? "N/A",
                    title = f.Title,
                    severity = f.Severity.ToString(),
                    riskScore = f.RiskScore,
                    isKev = f.IsKev ? "悪用確認済み (CISA KEV)" : "未確認",
                    reachability = f.Reachability.ToString(),
                    filePath = f.FilePath,
                    status = f.Status.ToString(),
                    vexJustification = vex != null ? $"{vex.Justification}: {vex.ImpactStatement}" : "未適用"
                };
            }),
            auditConclusion = new
            {
                evaluation = findings.Count(f => f.Severity == FindingSeverity.Critical && f.Status == FindingStatus.Open) == 0
                    ? "基準適合：未トリアージの重大脆弱性（Critical）は存在しません。"
                    : "要注意：直ちに対処が必要な重大脆弱性（Critical）が残存しています。",
                requiredActions = "経済産業省ガイドライン第4章に基づき、オープン状態の脆弱性に対する修正パッチ適用およびOpenVEXによる影響有無評価を継続実施してください。"
            }
        };

        var json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
        return Encoding.UTF8.GetBytes(json);
    }

    private static byte[] ExportJson(IReadOnlyList<Domain.Entities.Finding> findings)
    {
        var json = JsonSerializer.Serialize(findings, new JsonSerializerOptions
        {
            WriteIndented = true
        });
        return Encoding.UTF8.GetBytes(json);
    }

    private static byte[] ExportCsv(IReadOnlyList<Domain.Entities.Finding> findings)
    {
        var sb = new StringBuilder();
        sb.AppendLine("FindingId,ProjectId,Title,Severity,RiskScore,Status,Category,Scanner,CWE,CVE,FilePath,StartLine,IsKEV,EPSS");

        foreach (var f in findings)
        {
            var title = EscapeCsv(f.Title);
            var filePath = EscapeCsv(f.FilePath ?? string.Empty);
            var line = $"{f.Id},{f.ProjectId},{title},{f.Severity},{f.RiskScore:F2},{f.Status},{f.Category},{f.ScannerName},{f.CweId},{f.CveId},{filePath},{f.StartLine},{f.IsKev},{f.EpssScore?.ToString("F4") ?? ""}";
            sb.AppendLine(line);
        }

        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    private static string EscapeCsv(string val)
    {
        if (val.Contains(',') || val.Contains('"') || val.Contains('\n') || val.Contains('\r'))
        {
            return $"\"{val.Replace("\"", "\"\"")}\"";
        }
        return val;
    }

    private static byte[] ExportSarif(IReadOnlyList<Domain.Entities.Finding> findings)
    {
        var results = findings.Select(f => new
        {
            ruleId = f.CveId ?? f.CweId ?? "SEC-FINDING",
            level = f.Severity switch
            {
                FindingSeverity.Critical or FindingSeverity.High => "error",
                FindingSeverity.Medium => "warning",
                FindingSeverity.Low => "note",
                _ => "none"
            },
            message = new { text = f.Description },
            locations = new[]
            {
                new
                {
                    physicalLocation = new
                    {
                        artifactLocation = new { uri = f.FilePath ?? "unknown" },
                        region = new
                        {
                            startLine = f.StartLine ?? 1,
                            endLine = f.EndLine ?? f.StartLine ?? 1
                        }
                    }
                }
            },
            properties = new
            {
                riskScore = f.RiskScore,
                status = f.Status.ToString(),
                category = f.Category.ToString(),
                scanner = f.ScannerName,
                isKev = f.IsKev,
                epss = f.EpssScore
            }
        });

        var sarifDoc = new
        {
            version = "2.1.0",
            runs = new[]
            {
                new
                {
                    tool = new
                    {
                        driver = new
                        {
                            name = "PktSecurityPlatform",
                            version = "1.0.0"
                        }
                    },
                    results = results.ToArray()
                }
            }
        };

        var json = JsonSerializer.Serialize(sarifDoc, new JsonSerializerOptions { WriteIndented = true });
        return Encoding.UTF8.GetBytes(json);
    }
}
