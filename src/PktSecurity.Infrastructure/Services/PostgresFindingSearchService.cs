using System.Text;
using Microsoft.EntityFrameworkCore;
using PktSecurity.Application.Common.Interfaces;
using PktSecurity.Application.DTOs;
using PktSecurity.Infrastructure.Data;

namespace PktSecurity.Infrastructure.Services;

public class PostgresFindingSearchService : IFindingSearchService
{
    private readonly AppDbContext _context;

    public PostgresFindingSearchService(AppDbContext context)
    {
        _context = context;
    }

    public async Task<PagedResult<FindingSummaryDto>> SearchFindingsAsync(
        FindingSearchQuery query,
        CancellationToken cancellationToken = default)
    {
        var limit = Math.Clamp(query.Limit ?? 50, 1, 200);

        var baseQuery = _context.Findings.AsNoTracking().AsQueryable();

        if (query.ProjectId.HasValue)
        {
            baseQuery = baseQuery.Where(f => f.ProjectId == query.ProjectId.Value);
        }

        if (query.Severity.HasValue)
        {
            baseQuery = baseQuery.Where(f => f.Severity == query.Severity.Value);
        }

        if (query.Status.HasValue)
        {
            baseQuery = baseQuery.Where(f => f.Status == query.Status.Value);
        }

        if (query.Category.HasValue)
        {
            baseQuery = baseQuery.Where(f => f.Category == query.Category.Value);
        }

        if (query.IsKev.HasValue)
        {
            baseQuery = baseQuery.Where(f => f.IsKev == query.IsKev.Value);
        }

        if (!string.IsNullOrWhiteSpace(query.Keyword))
        {
            var keyword = query.Keyword.Trim();
            baseQuery = baseQuery.Where(f =>
                f.Title.Contains(keyword) ||
                (f.FilePath != null && f.FilePath.Contains(keyword)) ||
                (f.CveId != null && f.CveId.Contains(keyword)) ||
                (f.CweId != null && f.CweId.Contains(keyword)));
        }

        // Keyset pagination cursor decoding
        var pagedQuery = baseQuery;
        if (!string.IsNullOrWhiteSpace(query.Cursor))
        {
            try
            {
                var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(query.Cursor));
                var parts = decoded.Split('_');
                if (parts.Length == 2 &&
                    double.TryParse(parts[0], System.Globalization.CultureInfo.InvariantCulture, out var cursorScore) &&
                    Guid.TryParse(parts[1], out var cursorId))
                {
                    pagedQuery = pagedQuery.Where(f =>
                        f.RiskScore < cursorScore ||
                        (Math.Abs(f.RiskScore - cursorScore) < 0.0001 && f.Id.CompareTo(cursorId) < 0));
                }
            }
            catch
            {
                // If invalid cursor, ignore and start from beginning
            }
        }

        // Compute totalCount on first page or when requested without cursor
        var totalCount = string.IsNullOrWhiteSpace(query.Cursor)
            ? await baseQuery.CountAsync(cancellationToken)
            : 0;

        var findings = await pagedQuery
            .OrderByDescending(f => f.RiskScore)
            .ThenByDescending(f => f.Id)
            .Take(limit + 1)
            .Select(f => new FindingSummaryDto
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
            })
            .ToListAsync(cancellationToken);

        var hasMore = findings.Count > limit;
        var items = hasMore ? findings.Take(limit).ToList() : findings;

        string? nextCursor = null;
        if (hasMore && items.Count > 0)
        {
            var last = items[^1];
            var rawCursor = $"{last.RiskScore.ToString("F4", System.Globalization.CultureInfo.InvariantCulture)}_{last.Id}";
            nextCursor = Convert.ToBase64String(Encoding.UTF8.GetBytes(rawCursor));
        }

        return new PagedResult<FindingSummaryDto>
        {
            Items = items,
            NextCursor = nextCursor,
            HasMore = hasMore,
            TotalCount = totalCount
        };
    }

    public async Task<FindingDetailDto?> GetFindingDetailAsync(
        Guid findingId,
        CancellationToken cancellationToken = default)
    {
        var finding = await _context.Findings
            .AsNoTracking()
            .Include(f => f.Evidences)
            .Include(f => f.StatusHistory)
            .Include(f => f.RiskAssessments)
            .FirstOrDefaultAsync(f => f.Id == findingId, cancellationToken);

        if (finding == null) return null;

        var latestRa = finding.RiskAssessments.OrderByDescending(r => r.CalculatedAt).FirstOrDefault();

        return new FindingDetailDto
        {
            Id = finding.Id,
            ProjectId = finding.ProjectId,
            Title = finding.Title,
            Description = finding.Description,
            Severity = finding.Severity,
            RiskScore = finding.RiskScore,
            Confidence = finding.Confidence,
            Status = finding.Status,
            Category = finding.Category,
            ScannerName = finding.ScannerName,
            CweId = finding.CweId,
            CveId = finding.CveId,
            PackagePurl = finding.PackagePurl,
            InstalledVersion = finding.InstalledVersion,
            FixedVersion = finding.FixedVersion,
            FilePath = finding.FilePath,
            StartLine = finding.StartLine,
            EndLine = finding.EndLine,
            EnclosingSymbol = finding.EnclosingSymbol,
            IsKev = finding.IsKev,
            EpssScore = finding.EpssScore,
            Reachability = finding.Reachability,
            CorrelationGroupId = finding.CorrelationGroupId,
            PrimaryFingerprint = finding.PrimaryFingerprint,
            SecondaryFingerprint = finding.SecondaryFingerprint,
            OccurrenceCount = finding.OccurrenceCount,
            CreatedAt = finding.CreatedAt,
            UpdatedAt = finding.UpdatedAt,
            LatestRiskAssessment = latestRa == null ? null : new RiskAssessmentDto
            {
                Id = latestRa.Id,
                FinalScore = latestRa.FinalScore,
                BaseSeverityScore = latestRa.BaseSeverityScore,
                ThreatScore = latestRa.ThreatScore,
                ReachabilityScore = latestRa.ReachabilityScore,
                AssetMultiplier = latestRa.AssetMultiplier,
                FormulaVersion = latestRa.FormulaVersion,
                CvssScore = latestRa.CvssScore,
                IsKev = latestRa.IsKev,
                EpssScore = latestRa.EpssScore,
                Reachability = latestRa.Reachability,
                MissingInputs = System.Text.Json.JsonSerializer.Deserialize<List<string>>(latestRa.MissingInputsJson) ?? new List<string>(),
                CalculatedAt = latestRa.CalculatedAt
            },
            Evidences = finding.Evidences.Select(e => new FindingEvidenceDto
            {
                Id = e.Id,
                CodeSnippetRedacted = e.CodeSnippetRedacted,
                CodeFlowJson = e.CodeFlowJson,
                RawSarifResultJson = e.RawSarifResultJson,
                CreatedAt = e.CreatedAt
            }).ToList(),
            StatusHistory = finding.StatusHistory.Select(h => new FindingStatusHistoryDto
            {
                Id = h.Id,
                FromStatus = h.FromStatus,
                ToStatus = h.ToStatus,
                ChangedByUserId = h.ChangedByUserId,
                Reason = h.Reason,
                ApprovedByUserId = h.ApprovedByUserId,
                CreatedAt = h.CreatedAt
            }).ToList()
        };
    }
}
