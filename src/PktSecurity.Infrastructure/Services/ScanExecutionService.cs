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
using PktSecurity.Infrastructure.Scanners;

namespace PktSecurity.Infrastructure.Services;

public class ScanExecutionService
{
    private readonly AppDbContext _context;
    private readonly IJobQueueProvider _jobQueue;
    private readonly ScannerRegistry _scannerRegistry;
    private readonly ITenantContext _tenantContext;
    private readonly ILogger<ScanExecutionService> _logger;

    public ScanExecutionService(
        AppDbContext context,
        IJobQueueProvider jobQueue,
        ScannerRegistry scannerRegistry,
        ITenantContext tenantContext,
        ILogger<ScanExecutionService> logger)
    {
        _context = context;
        _jobQueue = jobQueue;
        _scannerRegistry = scannerRegistry;
        _tenantContext = tenantContext;
        _logger = logger;
    }

    public async Task ProcessJobAsync(ScanJob job, string workerId, CancellationToken cancellationToken = default)
    {
        _tenantContext.SetTenantId(job.TenantId);
        var stopwatch = Stopwatch.StartNew();

        // Start background heartbeat
        using var heartbeatCts = new CancellationTokenSource();
        var heartbeatTask = Task.Run(async () =>
        {
            while (!heartbeatCts.Token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(20), heartbeatCts.Token);
                    await _jobQueue.ExtendLeaseAsync(job.Id, workerId, TimeSpan.FromMinutes(2), heartbeatCts.Token);
                }
                catch
                {
                    // Heartbeat cancellation or network blip
                }
            }
        }, heartbeatCts.Token);

        string? tempOutputFile = null;

        try
        {
            var scan = await _context.Scans
                .Include(s => s.Project)
                .ThenInclude(p => p!.Repositories)
                .FirstOrDefaultAsync(s => s.Id == job.ScanId, cancellationToken);

            if (scan == null)
            {
                await _jobQueue.FailJobAsync(job.Id, $"Scan {job.ScanId} not found", cancellationToken);
                return;
            }

            scan.Status = ScanStatus.Running;
            await _context.SaveChangesAsync(cancellationToken);

            // Determine target directory
            string targetDir = Directory.GetCurrentDirectory();
            var repo = scan.Project?.Repositories.FirstOrDefault();
            if (repo != null && !string.IsNullOrWhiteSpace(repo.RepoUrl) && Directory.Exists(repo.RepoUrl))
            {
                targetDir = repo.RepoUrl;
            }

            tempOutputFile = Path.Combine(Path.GetTempPath(), $"pkt_scan_{job.Id}_{Guid.NewGuid():N}.sarif");

            var scanContext = new ScannerScanContext(
                job.TenantId,
                scan.ProjectId,
                scan.Id,
                targetDir,
                tempOutputFile);

            var adapter = _scannerRegistry.GetAdapter(job.ScannerName);
            _logger.LogInformation("Executing scanner {ScannerName} for job {JobId} on directory {TargetDir}",
                adapter.ScannerName, job.Id, targetDir);

            var scanResult = await adapter.ScanAsync(scanContext, cancellationToken);

            if (!scanResult.Success)
            {
                throw new InvalidOperationException($"Scanner {job.ScannerName} failed: {scanResult.ErrorMessage}");
            }

            // Ingest and deduplicate findings
            await IngestFindingsAsync(scan, scanResult.Findings, cancellationToken);

            scan.Status = ScanStatus.Completed;
            scan.CompletedAt = DateTime.UtcNow;

            stopwatch.Stop();
            await _jobQueue.CompleteJobAsync(job.Id, stopwatch.ElapsedMilliseconds, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);

            _logger.LogInformation("Successfully completed scan job {JobId} in {ElapsedMs}ms with {Count} findings",
                job.Id, stopwatch.ElapsedMilliseconds, scanResult.Findings.Count);
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            _logger.LogError(ex, "Failed to execute scan job {JobId}", job.Id);
            await _jobQueue.FailJobAsync(job.Id, ex.Message, cancellationToken);

            var scan = await _context.Scans.FirstOrDefaultAsync(s => s.Id == job.ScanId, cancellationToken);
            if (scan != null)
            {
                scan.Status = ScanStatus.Failed;
                scan.ErrorMessage = ex.Message;
                scan.CompletedAt = DateTime.UtcNow;
                await _context.SaveChangesAsync(cancellationToken);
            }
        }
        finally
        {
            heartbeatCts.Cancel();
            try { await heartbeatTask; } catch { }

            // Ensure temporary output file is deleted
            if (tempOutputFile != null && File.Exists(tempOutputFile))
            {
                try { File.Delete(tempOutputFile); } catch { }
            }
        }
    }

    private async Task IngestFindingsAsync(
        Scan scan,
        IReadOnlyList<NormalizedFindingDto> findings,
        CancellationToken cancellationToken)
    {
        var project = scan.Project ?? await _context.Projects.FirstAsync(p => p.Id == scan.ProjectId, cancellationToken);

        // Fetch existing findings for this project to perform deduplication
        var existingFindings = await _context.Findings
            .Where(f => f.ProjectId == scan.ProjectId)
            .ToListAsync(cancellationToken);

        var existingByPrimary = existingFindings
            .ToDictionary(f => f.PrimaryFingerprint, StringComparer.OrdinalIgnoreCase);

        var existingBySecondary = existingFindings
            .Where(f => f.Status != FindingStatus.Closed)
            .GroupBy(f => f.SecondaryFingerprint, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        foreach (var dto in findings)
        {
            var primaryFp = FingerprintCalculator.ComputePrimary(
                dto.ScannerName,
                dto.RuleId ?? dto.CveId ?? dto.CweId ?? "GENERIC",
                dto.FilePath ?? dto.PackagePurl,
                dto.StartLine);

            var secondaryFp = FingerprintCalculator.ComputeSecondary(
                scan.TenantId,
                scan.ProjectId,
                dto.Category.ToString(),
                dto.CweId ?? dto.CveId ?? "GENERIC",
                dto.FilePath,
                dto.EnclosingSymbol,
                dto.CodeSnippet);

            var riskBreakdown = RiskScoreCalculator.Calculate(
                dto.Severity,
                dto.IsKev,
                dto.EpssScore,
                dto.Reachability,
                project.BusinessCriticality,
                project.IsInternetFacing);

            // 1. Check Primary Fingerprint
            if (existingByPrimary.TryGetValue(primaryFp, out var existing))
            {
                existing.OccurrenceCount++;
                existing.LastSeenScanId = scan.Id;
                existing.UpdatedAt = DateTime.UtcNow;
                existing.RiskScore = riskBreakdown.FinalScore;

                _context.RiskAssessments.Add(new RiskAssessment
                {
                    Id = Guid.NewGuid(),
                    TenantId = scan.TenantId,
                    FindingId = existing.Id,
                    FinalScore = riskBreakdown.FinalScore,
                    BaseSeverityScore = riskBreakdown.BaseSeverityScore,
                    ThreatScore = riskBreakdown.ThreatScore,
                    ReachabilityScore = riskBreakdown.ReachabilityScore,
                    AssetMultiplier = riskBreakdown.AssetMultiplier,
                    FormulaVersion = "1.0",
                    CvssScore = null,
                    IsKev = dto.IsKev,
                    EpssScore = dto.EpssScore,
                    Reachability = dto.Reachability,
                    MissingInputsJson = JsonSerializer.Serialize(riskBreakdown.MissingInputs),
                    CalculatedAt = DateTime.UtcNow
                });
                continue;
            }

            // 2. Check Secondary Fingerprint (Location Drift Resilience)
            if (existingBySecondary.TryGetValue(secondaryFp, out var driftExisting))
            {
                driftExisting.OccurrenceCount++;
                driftExisting.LastSeenScanId = scan.Id;
                driftExisting.FilePath = dto.FilePath ?? driftExisting.FilePath;
                driftExisting.StartLine = dto.StartLine;
                driftExisting.EndLine = dto.EndLine;
                driftExisting.UpdatedAt = DateTime.UtcNow;
                driftExisting.RiskScore = riskBreakdown.FinalScore;

                _context.RiskAssessments.Add(new RiskAssessment
                {
                    Id = Guid.NewGuid(),
                    TenantId = scan.TenantId,
                    FindingId = driftExisting.Id,
                    FinalScore = riskBreakdown.FinalScore,
                    BaseSeverityScore = riskBreakdown.BaseSeverityScore,
                    ThreatScore = riskBreakdown.ThreatScore,
                    ReachabilityScore = riskBreakdown.ReachabilityScore,
                    AssetMultiplier = riskBreakdown.AssetMultiplier,
                    FormulaVersion = "1.0",
                    CvssScore = null,
                    IsKev = dto.IsKev,
                    EpssScore = dto.EpssScore,
                    Reachability = dto.Reachability,
                    MissingInputsJson = JsonSerializer.Serialize(riskBreakdown.MissingInputs),
                    CalculatedAt = DateTime.UtcNow
                });
                continue;
            }

            // 3. New Finding
            var newFinding = new Finding
            {
                Id = Guid.NewGuid(),
                TenantId = scan.TenantId,
                ProjectId = scan.ProjectId,
                Title = dto.Title,
                Description = dto.Description,
                Severity = dto.Severity,
                RiskScore = riskBreakdown.FinalScore,
                Confidence = 1.0,
                Status = FindingStatus.Open,
                Category = dto.Category,
                ScannerName = dto.ScannerName,
                CweId = dto.CweId,
                CveId = dto.CveId,
                PackagePurl = dto.PackagePurl,
                InstalledVersion = dto.InstalledVersion,
                FixedVersion = dto.FixedVersion,
                FilePath = dto.FilePath,
                StartLine = dto.StartLine,
                EndLine = dto.EndLine,
                EnclosingSymbol = dto.EnclosingSymbol,
                IsKev = dto.IsKev,
                EpssScore = dto.EpssScore,
                Reachability = dto.Reachability,
                PrimaryFingerprint = primaryFp,
                SecondaryFingerprint = secondaryFp,
                OccurrenceCount = 1,
                FirstSeenScanId = scan.Id,
                LastSeenScanId = scan.Id,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            var evidence = new FindingEvidence
            {
                Id = Guid.NewGuid(),
                TenantId = scan.TenantId,
                FindingId = newFinding.Id,
                CodeSnippetRedacted = dto.CodeSnippet,
                RawSarifResultJson = dto.RawResultJson,
                CreatedAt = DateTime.UtcNow
            };

            newFinding.Evidences.Add(evidence);

            _context.Findings.Add(newFinding);

            _context.RiskAssessments.Add(new RiskAssessment
            {
                Id = Guid.NewGuid(),
                TenantId = scan.TenantId,
                FindingId = newFinding.Id,
                FinalScore = riskBreakdown.FinalScore,
                BaseSeverityScore = riskBreakdown.BaseSeverityScore,
                ThreatScore = riskBreakdown.ThreatScore,
                ReachabilityScore = riskBreakdown.ReachabilityScore,
                AssetMultiplier = riskBreakdown.AssetMultiplier,
                FormulaVersion = "1.0",
                CvssScore = null,
                IsKev = dto.IsKev,
                EpssScore = dto.EpssScore,
                Reachability = dto.Reachability,
                MissingInputsJson = JsonSerializer.Serialize(riskBreakdown.MissingInputs),
                CalculatedAt = DateTime.UtcNow
            });

            existingByPrimary[primaryFp] = newFinding;
            existingBySecondary[secondaryFp] = newFinding;
        }

        // Cross-scanner correlation across all project findings
        var allProjectFindings = existingFindings.Concat(_context.Findings.Local).Distinct().ToList();
        CrossScannerCorrelationService.CorrelateFindings(allProjectFindings);

        await _context.SaveChangesAsync(cancellationToken);
    }
}
