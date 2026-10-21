using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using PktSecurity.Application.Common.Interfaces;
using PktSecurity.Domain.Enums;
using PktSecurity.Infrastructure.Data;

namespace PktSecurity.Api.Endpoints;

public class DashboardSummaryDto
{
    public int TotalFindings { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
    public int InfoCount { get; set; }
    public int KevCount { get; set; }
    public double AverageRiskScore { get; set; }
    public int TotalProjects { get; set; }
    public int ActiveScansCount { get; set; }
    public IReadOnlyList<TopRiskFindingDto> TopRiskFindings { get; set; } = Array.Empty<TopRiskFindingDto>();
}

public class TopRiskFindingDto
{
    public Guid Id { get; set; }
    public Guid ProjectId { get; set; }
    public string ProjectName { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public FindingSeverity Severity { get; set; }
    public double RiskScore { get; set; }
    public string ScannerName { get; set; } = string.Empty;
    public string? RuleId { get; set; }
    public string? CveId { get; set; }
    public string? FilePath { get; set; }
    public int? StartLine { get; set; }
    public bool IsKev { get; set; }
    public double? EpssScore { get; set; }
    public Reachability Reachability { get; set; }
    public FindingStatus Status { get; set; }
    public DateTime CreatedAt { get; set; }
}

public static class DashboardEndpoints
{
    public static void MapDashboardEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/dashboard").WithTags("Dashboard").RequireAuthorization();

        group.MapGet("/summary", async (
            AppDbContext db,
            ITenantContext tenantContext,
            IMemoryCache cache,
            CancellationToken cancellationToken) =>
        {
            var tenantId = tenantContext.CurrentTenantId;
            if (tenantId == null)
            {
                return Results.Unauthorized();
            }

            var cacheKey = $"dashboard_summary_{tenantId.Value}";
            if (cache.TryGetValue(cacheKey, out DashboardSummaryDto? cached) && cached != null)
            {
                return Results.Ok(cached);
            }

            var connection = db.Database.GetDbConnection();
            if (connection.State != System.Data.ConnectionState.Open)
            {
                await connection.OpenAsync(cancellationToken);
            }

            // Single high-efficiency aggregation query using PostgreSQL FILTER clause
            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                SELECT
                    COUNT(*)::int AS total,
                    COUNT(*) FILTER (WHERE severity = 0)::int AS critical_count,
                    COUNT(*) FILTER (WHERE severity = 1)::int AS high_count,
                    COUNT(*) FILTER (WHERE severity = 2)::int AS medium_count,
                    COUNT(*) FILTER (WHERE severity = 3)::int AS low_count,
                    COUNT(*) FILTER (WHERE severity = 4)::int AS info_count,
                    COUNT(*) FILTER (WHERE is_kev = true)::int AS kev_count,
                    COALESCE(AVG(risk_score), 0.0)::float8 AS avg_score
                FROM findings
                WHERE tenant_id = @tenantId;
            ";
            var pTenant = cmd.CreateParameter();
            pTenant.ParameterName = "tenantId";
            pTenant.Value = tenantId.Value;
            cmd.Parameters.Add(pTenant);

            int totalFindings = 0, criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0, infoCount = 0, kevCount = 0;
            double avgScore = 0.0;

            using (var reader = await cmd.ExecuteReaderAsync(cancellationToken))
            {
                if (await reader.ReadAsync(cancellationToken))
                {
                    totalFindings = reader.GetInt32(0);
                    criticalCount = reader.GetInt32(1);
                    highCount = reader.GetInt32(2);
                    mediumCount = reader.GetInt32(3);
                    lowCount = reader.GetInt32(4);
                    infoCount = reader.GetInt32(5);
                    kevCount = reader.GetInt32(6);
                    avgScore = reader.GetDouble(7);
                }
            }

            var findingsQuery = db.Findings.AsNoTracking().Where(f => f.TenantId == tenantId.Value);

            var totalProjects = await db.Projects.AsNoTracking().CountAsync(p => p.TenantId == tenantId.Value, cancellationToken);
            var activeScans = await db.Scans.AsNoTracking().CountAsync(s => s.TenantId == tenantId.Value && (s.Status == ScanStatus.Queued || s.Status == ScanStatus.Running), cancellationToken);

            var topFindings = await findingsQuery
                .OrderByDescending(f => f.RiskScore)
                .ThenByDescending(f => f.Id)
                .Take(10)
                .Select(f => new TopRiskFindingDto
                {
                    Id = f.Id,
                    ProjectId = f.ProjectId,
                    ProjectName = f.Project != null ? f.Project.Name : string.Empty,
                    Title = f.Title,
                    Severity = f.Severity,
                    RiskScore = f.RiskScore,
                    ScannerName = f.ScannerName,
                    RuleId = f.CweId ?? f.CveId,
                    CveId = f.CveId,
                    FilePath = f.FilePath,
                    StartLine = f.StartLine,
                    IsKev = f.IsKev,
                    EpssScore = f.EpssScore,
                    Reachability = f.Reachability,
                    Status = f.Status,
                    CreatedAt = f.CreatedAt
                })
                .ToListAsync(cancellationToken);

            var summary = new DashboardSummaryDto
            {
                TotalFindings = totalFindings,
                CriticalCount = criticalCount,
                HighCount = highCount,
                MediumCount = mediumCount,
                LowCount = lowCount,
                InfoCount = infoCount,
                KevCount = kevCount,
                AverageRiskScore = Math.Round(avgScore, 2),
                TotalProjects = totalProjects,
                ActiveScansCount = activeScans,
                TopRiskFindings = topFindings
            };

            cache.Set(cacheKey, summary, TimeSpan.FromSeconds(5));
            return Results.Ok(summary);
        });
    }
}
