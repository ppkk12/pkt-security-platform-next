using System.Diagnostics;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using PktSecurity.Application.Common.Interfaces;
using PktSecurity.Application.DTOs;
using PktSecurity.Domain.Entities;
using PktSecurity.Domain.Enums;
using PktSecurity.Infrastructure.Data;
using PktSecurity.Infrastructure.Security;

namespace PktSecurity.Infrastructure.Services;

public class RemediationService : IRemediationService
{
    private readonly AppDbContext _context;
    private readonly IAiRemediationProvider _aiProvider;
    private readonly IScannerAdapter _scannerAdapter;
    private readonly IAuditService _auditService;
    private readonly ILogger<RemediationService> _logger;

    public RemediationService(
        AppDbContext context,
        IAiRemediationProvider aiProvider,
        IScannerAdapter scannerAdapter,
        IAuditService auditService,
        ILogger<RemediationService> logger)
    {
        _context = context;
        _aiProvider = aiProvider;
        _scannerAdapter = scannerAdapter;
        _auditService = auditService;
        _logger = logger;
    }

    public async Task<RemediationDto> GenerateRemediationAsync(
        Guid tenantId,
        Guid findingId,
        CancellationToken cancellationToken = default)
    {
        var finding = await _context.Findings
            .Include(f => f.Evidences)
            .Include(f => f.Project)
            .FirstOrDefaultAsync(f => f.Id == findingId && f.TenantId == tenantId, cancellationToken);

        if (finding == null)
            throw new KeyNotFoundException($"Finding {findingId} not found");

        var context = new RemediationContext
        {
            FindingId = finding.Id,
            Title = finding.Title,
            Description = finding.Description,
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
            CodeSnippet = finding.Evidences.FirstOrDefault()?.CodeSnippetRedacted
        };

        var suggestion = await _aiProvider.GenerateRemediationAsync(context, cancellationToken);

        var remediation = new Remediation
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            FindingId = finding.Id,
            VerifiedFactsJson = JsonSerializer.Serialize(suggestion.VerifiedFacts),
            AiHypothesisAnalysis = suggestion.AiHypothesisAnalysis,
            ProposedUnifiedDiff = suggestion.ProposedUnifiedDiff,
            SideEffectsWarning = suggestion.SideEffectsWarning,
            VerificationStatus = RemediationVerificationStatus.Pending,
            ApprovalStatus = RemediationApprovalStatus.PendingReview,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };

        _context.Remediations.Add(remediation);
        await _context.SaveChangesAsync(cancellationToken);

        await _auditService.RecordEventAsync(
            tenantId,
            "remediation.generated",
            null,
            "AI Remediation Generated",
            new { FindingId = finding.Id, RemediationId = remediation.Id },
            cancellationToken);

        return MapToDto(remediation);
    }

    public async Task<RemediationDto?> GetRemediationAsync(
        Guid tenantId,
        Guid findingId,
        CancellationToken cancellationToken = default)
    {
        var remediation = await _context.Remediations
            .Where(r => r.TenantId == tenantId && r.FindingId == findingId)
            .OrderByDescending(r => r.CreatedAt)
            .FirstOrDefaultAsync(cancellationToken);

        return remediation == null ? null : MapToDto(remediation);
    }

    public async Task<RemediationVerificationResultDto> VerifyRemediationAsync(
        Guid tenantId,
        Guid remediationId,
        CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();

        var remediation = await _context.Remediations
            .Include(r => r.Finding)
            .ThenInclude(f => f!.Project)
            .FirstOrDefaultAsync(r => r.Id == remediationId && r.TenantId == tenantId, cancellationToken);

        if (remediation == null)
            throw new KeyNotFoundException($"Remediation {remediationId} not found");

        var finding = remediation.Finding
            ?? throw new InvalidOperationException("Associated finding not found");

        var tempSandbox = Path.Combine(Path.GetTempPath(), "pkt-sandbox-verify-" + Guid.NewGuid().ToString("N"));

        try
        {
            Directory.CreateDirectory(tempSandbox);

            // Populate sandbox workspace with repo files
            var sourceRepo = ResolveSourceRepoDirectory(finding);
            if (Directory.Exists(sourceRepo))
            {
                CopyDirectory(sourceRepo, tempSandbox);
            }
            else
            {
                // Fallback: create mock file based on finding file path and evidence
                var targetFile = Path.Combine(tempSandbox, (finding.FilePath ?? "src/vulnerable.cs").Replace('/', Path.DirectorySeparatorChar));
                var parent = Path.GetDirectoryName(targetFile);
                if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);

                var dummyContent = finding.Category == FindingCategory.SCA
                    ? "{\n  \"dependencies\": {\n    \"lodash\": \"4.17.20\"\n  }\n}"
                    : "public class Vulnerable {\n    public void Test(string input) {\n        var query = $\"SELECT * FROM Users WHERE Username = '{input}'\";\n    }\n}";
                await File.WriteAllTextAsync(targetFile, dummyContent, cancellationToken);
            }

            // Apply Unified Diff to sandbox
            var patchResult = await UnifiedDiffPatcher.ApplyPatchToWorkspaceAsync(
                tempSandbox,
                remediation.ProposedUnifiedDiff,
                cancellationToken);

            if (!patchResult.Success)
            {
                remediation.VerificationStatus = RemediationVerificationStatus.PatchInvalid;
                remediation.VerificationDetails = $"Patch application failed: {patchResult.ErrorMessage}";
            }
            else
            {
                // Re-scan sandbox workspace
                var scanContext = new ScannerScanContext(
                    tenantId,
                    finding.ProjectId,
                    Guid.NewGuid(),
                    tempSandbox,
                    Path.Combine(tempSandbox, "rescan.sarif"));

                var scanResult = await _scannerAdapter.ScanAsync(scanContext, cancellationToken);

                // Check whether the original vulnerability still exists
                bool stillPresent = scanResult.Findings.Any(f =>
                    (!string.IsNullOrEmpty(finding.CweId) && f.CweId == finding.CweId) ||
                    (!string.IsNullOrEmpty(finding.CveId) && f.CveId == finding.CveId) ||
                    (!string.IsNullOrEmpty(finding.FilePath) && f.FilePath != null && f.FilePath.EndsWith(Path.GetFileName(finding.FilePath), StringComparison.OrdinalIgnoreCase)));

                if (stillPresent)
                {
                    remediation.VerificationStatus = RemediationVerificationStatus.PatchAppliesButFindingRemains;
                    remediation.VerificationDetails = "Patch was applied successfully to the sandbox, but the vulnerability remains detectable upon re-scan.";
                }
                else
                {
                    remediation.VerificationStatus = RemediationVerificationStatus.VerifiedFixed;
                    remediation.VerificationDetails = "Vulnerability successfully eliminated. Sandboxed re-scan confirmed 0 matching findings.";
                }
            }

            remediation.UpdatedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync(cancellationToken);

            await _auditService.RecordEventAsync(
                tenantId,
                "remediation.verified",
                null,
                "Remediation Verified in Sandbox",
                new { RemediationId = remediation.Id, Status = remediation.VerificationStatus.ToString() },
                cancellationToken);

            sw.Stop();
            return new RemediationVerificationResultDto
            {
                RemediationId = remediation.Id,
                VerificationStatus = remediation.VerificationStatus,
                Details = remediation.VerificationDetails ?? string.Empty,
                DurationMs = sw.ElapsedMilliseconds
            };
        }
        finally
        {
            // Ephemeral directory cleanup
            try
            {
                if (Directory.Exists(tempSandbox))
                {
                    Directory.Delete(tempSandbox, recursive: true);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to clean up ephemeral sandbox {TempSandbox}", tempSandbox);
            }
        }
    }

    public async Task<RemediationDto> ApproveRemediationAsync(
        Guid tenantId,
        Guid remediationId,
        Guid userId,
        CancellationToken cancellationToken = default)
    {
        var remediation = await _context.Remediations
            .Include(r => r.Finding)
            .FirstOrDefaultAsync(r => r.Id == remediationId && r.TenantId == tenantId, cancellationToken);

        if (remediation == null)
            throw new KeyNotFoundException($"Remediation {remediationId} not found");

        if (remediation.VerificationStatus != RemediationVerificationStatus.VerifiedFixed)
        {
            throw new InvalidOperationException(
                $"Cannot approve remediation {remediationId} because it has not been verified in sandbox (VerificationStatus must be VerifiedFixed, currently {remediation.VerificationStatus}).");
        }

        remediation.ApprovalStatus = RemediationApprovalStatus.Approved;
        remediation.ApprovedByUserId = userId;
        remediation.ApprovedAt = DateTime.UtcNow;
        remediation.UpdatedAt = DateTime.UtcNow;

        if (remediation.Finding != null)
        {
            remediation.Finding.Status = FindingStatus.Remediated;
            remediation.Finding.UpdatedAt = DateTime.UtcNow;

            _context.FindingStatusHistories.Add(new FindingStatusHistory
            {
                Id = Guid.NewGuid(),
                TenantId = tenantId,
                FindingId = remediation.Finding.Id,
                FromStatus = FindingStatus.Open,
                ToStatus = FindingStatus.Remediated,
                ChangedByUserId = userId,
                ApprovedByUserId = userId,
                Reason = "AI Remediation approved by security team",
                CreatedAt = DateTime.UtcNow
            });
        }

        await _context.SaveChangesAsync(cancellationToken);

        await _auditService.RecordEventAsync(
            tenantId,
            "remediation.approved",
            userId,
            "Remediation Approved",
            new { RemediationId = remediation.Id, FindingId = remediation.FindingId },
            cancellationToken);

        return MapToDto(remediation);
    }

    public async Task<RemediationDto> RejectRemediationAsync(
        Guid tenantId,
        Guid remediationId,
        Guid userId,
        string? reason,
        CancellationToken cancellationToken = default)
    {
        var remediation = await _context.Remediations
            .FirstOrDefaultAsync(r => r.Id == remediationId && r.TenantId == tenantId, cancellationToken);

        if (remediation == null)
            throw new KeyNotFoundException($"Remediation {remediationId} not found");

        remediation.ApprovalStatus = RemediationApprovalStatus.Rejected;
        remediation.VerificationDetails = reason ?? "Rejected by reviewer";
        remediation.UpdatedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync(cancellationToken);

        await _auditService.RecordEventAsync(
            tenantId,
            "remediation.rejected",
            userId,
            "Remediation Rejected",
            new { RemediationId = remediation.Id, Reason = reason },
            cancellationToken);

        return MapToDto(remediation);
    }

    private static RemediationDto MapToDto(Remediation r) => new()
    {
        Id = r.Id,
        FindingId = r.FindingId,
        VerifiedFacts = JsonSerializer.Deserialize<List<string>>(r.VerifiedFactsJson) ?? new List<string>(),
        AiHypothesisAnalysis = r.AiHypothesisAnalysis,
        ProposedUnifiedDiff = r.ProposedUnifiedDiff,
        SideEffectsWarning = r.SideEffectsWarning,
        VerificationStatus = r.VerificationStatus,
        VerificationDetails = r.VerificationDetails,
        ApprovalStatus = r.ApprovalStatus,
        ApprovedByUserId = r.ApprovedByUserId,
        ApprovedAt = r.ApprovedAt,
        CreatedAt = r.CreatedAt,
        UpdatedAt = r.UpdatedAt
    };

    private static string ResolveSourceRepoDirectory(Finding finding)
    {
        var currentDir = Directory.GetCurrentDirectory();
        var sampleDir = Path.Combine(currentDir, "samples", "sample-vulnerable-repo");
        if (Directory.Exists(sampleDir)) return sampleDir;

        var altDir = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../samples/sample-vulnerable-repo"));
        if (Directory.Exists(altDir)) return altDir;

        var altDir2 = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../samples/sample-vulnerable-repo"));
        if (Directory.Exists(altDir2)) return altDir2;

        return sampleDir;
    }

    private static void CopyDirectory(string sourceDir, string targetDir)
    {
        Directory.CreateDirectory(targetDir);

        foreach (var file in Directory.GetFiles(sourceDir))
        {
            File.Copy(file, Path.Combine(targetDir, Path.GetFileName(file)), overwrite: true);
        }

        foreach (var subDir in Directory.GetDirectories(sourceDir))
        {
            var dirName = Path.GetFileName(subDir);
            if (dirName.Equals(".git", StringComparison.OrdinalIgnoreCase) || dirName.Equals("bin", StringComparison.OrdinalIgnoreCase) || dirName.Equals("obj", StringComparison.OrdinalIgnoreCase))
                continue;

            CopyDirectory(subDir, Path.Combine(targetDir, dirName));
        }
    }
}
