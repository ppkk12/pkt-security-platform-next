using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using PktSecurity.Application.Common.Interfaces;
using PktSecurity.Application.DTOs;
using PktSecurity.Domain.Entities;
using PktSecurity.Domain.Enums;
using PktSecurity.Infrastructure.Services;
using Xunit;

namespace PktSecurity.IntegrationTests;

public class MilestoneM2IntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public MilestoneM2IntegrationTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task M2_LineShift_LocationDriftRescan_MustPreserveTriageStatusAndNotDuplicateFindings()
    {
        var client = _factory.CreateClient();

        // 1. Authenticate as Tenant Admin
        var token = await AuthenticateTenantAdminAsync(client);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // 2. Prepare Isolated Temp Directory with Vulnerable Code
        var sampleRepoPath = ResolveSampleRepoPath();
        var tempRepoDir = Path.Combine(Path.GetTempPath(), $"pkt_drift_test_{Guid.NewGuid():N}");
        CopyDirectory(sampleRepoPath, tempRepoDir);

        try
        {
            // 3. Create Project
            var createProjResp = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest
            {
                Name = $"Drift Test {Guid.NewGuid():N}",
                Description = "Location drift resilience test project",
                BusinessCriticality = BusinessCriticality.High,
                IsInternetFacing = true,
                DataSensitivity = "Confidential",
                RepositoryUrl = tempRepoDir
            });
            createProjResp.StatusCode.Should().Be(HttpStatusCode.Created);
            var project = await createProjResp.Content.ReadFromJsonAsync<ProjectDto>();
            var projectId = project!.Id;

            // 4. Run First Scan
            var scan1Id = await TriggerAndProcessScanAsync(client, projectId, tempRepoDir);

            // Fetch initial findings
            var findingsResp1 = await client.GetAsync($"/api/v1/findings?projectId={projectId}&limit=100");
            findingsResp1.StatusCode.Should().Be(HttpStatusCode.OK);
            var paged1 = await findingsResp1.Content.ReadFromJsonAsync<PagedResult<FindingSummaryDto>>();
            paged1.Should().NotBeNull();
            var initialCount = paged1!.Items.Count;
            initialCount.Should().BeGreaterThan(0, "First scan must discover vulnerabilities");

            // Pick a SAST code finding in a source file
            var sastFinding = paged1.Items.First(f => f.Category == FindingCategory.SAST && f.StartLine.HasValue && f.FilePath != null);
            var targetFindingId = sastFinding.Id;
            var originalStartLine = sastFinding.StartLine!.Value;
            var targetFilePath = Path.Combine(tempRepoDir, sastFinding.FilePath!);

            File.Exists(targetFilePath).Should().BeTrue();

            // 5. Triage the finding: Mark as FalsePositive
            var patchResp = await client.PatchAsJsonAsync($"/api/v1/findings/{targetFindingId}/status", new
            {
                status = FindingStatus.FalsePositive,
                reason = "Reviewed by SecEng: Verified as safe internal test utility"
            });
            patchResp.StatusCode.Should().Be(HttpStatusCode.OK);

            // Verify triage status is FalsePositive
            var detailResp1 = await client.GetAsync($"/api/v1/findings/{targetFindingId}");
            var detail1 = await detailResp1.Content.ReadFromJsonAsync<FindingDetailDto>();
            detail1!.Status.Should().Be(FindingStatus.FalsePositive);
            detail1.StatusHistory.Should().Contain(h => h.ToStatus == FindingStatus.FalsePositive);

            // 6. Prepend exactly 10 lines of comments & empty lines to the vulnerable file
            var originalContent = await File.ReadAllLinesAsync(targetFilePath);
            var commentHeader = new[]
            {
                "// ==========================================",
                "// Header comment line 1 for drift test",
                "// Header comment line 2 for drift test",
                "",
                "// Header comment line 4 for drift test",
                "// Header comment line 5 for drift test",
                "",
                "// Header comment line 7 for drift test",
                "// Header comment line 8 for drift test",
                "// =========================================="
            };
            commentHeader.Length.Should().Be(10, "Must prepend exactly 10 lines");

            var shiftedContent = commentHeader.Concat(originalContent).ToArray();
            await File.WriteAllLinesAsync(targetFilePath, shiftedContent);

            // 7. Run Second Scan
            var scan2Id = await TriggerAndProcessScanAsync(client, projectId, tempRepoDir);
            scan2Id.Should().NotBe(scan1Id);

            // 8. Verify Results: NO Duplicate Finding Created!
            var findingsResp2 = await client.GetAsync($"/api/v1/findings?projectId={projectId}&limit=100");
            findingsResp2.StatusCode.Should().Be(HttpStatusCode.OK);
            var paged2 = await findingsResp2.Content.ReadFromJsonAsync<PagedResult<FindingSummaryDto>>();
            paged2.Should().NotBeNull();

            paged2!.Items.Count.Should().Be(initialCount,
                "Finding count must not increase after line-shifted re-scan (zero duplicates allowed)");

            // 9. Verify the triaged finding:
            // - start_line shifted by +10
            // - occurrence_count incremented to 2
            // - triage status is STILL FalsePositive!
            // - status history preserved!
            var detailResp2 = await client.GetAsync($"/api/v1/findings/{targetFindingId}");
            detailResp2.StatusCode.Should().Be(HttpStatusCode.OK);
            var detail2 = await detailResp2.Content.ReadFromJsonAsync<FindingDetailDto>();
            detail2.Should().NotBeNull();

            detail2!.StartLine.Should().Be(originalStartLine + 10,
                "StartLine must be updated to the shifted line (+10)");
            detail2.OccurrenceCount.Should().Be(2,
                "OccurrenceCount must increment on rescanning identical vulnerability");
            detail2.Status.Should().Be(FindingStatus.FalsePositive,
                "Triage status (FalsePositive) must be 100% preserved despite line shift");
            detail2.StatusHistory.Should().Contain(h => h.ToStatus == FindingStatus.FalsePositive && h.Reason!.Contains("SecEng"),
                "Past triage comments and history must remain fully intact");

            // 10. Verify Non-Imputation Principle in RiskAssessment
            detail2.LatestRiskAssessment.Should().NotBeNull();
            detail2.LatestRiskAssessment!.MissingInputs.Should().NotBeNull();
            // Since this is native-sast with no CVSS provided, CVSS should be in MissingInputs
            detail2.LatestRiskAssessment.MissingInputs.Should().Contain("CVSS");
            detail2.LatestRiskAssessment.CvssScore.Should().BeNull("Missing CVSS must not be imputed or guessed with fake numbers");
        }
        finally
        {
            if (Directory.Exists(tempRepoDir))
            {
                try { Directory.Delete(tempRepoDir, true); } catch { }
            }
        }
    }

    [Fact]
    public async Task M2_CycloneDx_FastRescan_And_OpenVex_MustWorkCorrectly()
    {
        var client = _factory.CreateClient();

        // 1. Authenticate as Tenant Admin
        var token = await AuthenticateTenantAdminAsync(client);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // 2. Create Project for SBOM Testing
        var createProjResp = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest
        {
            Name = $"SBOM Project {Guid.NewGuid():N}",
            Description = "CycloneDX and OpenVEX test project",
            BusinessCriticality = BusinessCriticality.High,
            IsInternetFacing = true,
            DataSensitivity = "Internal"
        });
        createProjResp.StatusCode.Should().Be(HttpStatusCode.Created);
        var project = await createProjResp.Content.ReadFromJsonAsync<ProjectDto>();
        var projectId = project!.Id;

        // 3. Import CycloneDX 1.6 SBOM
        var sbomFilePath = ResolveSampleSbomPath();
        File.Exists(sbomFilePath).Should().BeTrue($"SBOM file must exist at {sbomFilePath}");

        var sbomJson = await File.ReadAllTextAsync(sbomFilePath);
        var uploadReq = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/projects/{projectId}/sbom/upload")
        {
            Content = new StringContent(sbomJson, System.Text.Encoding.UTF8, "application/json")
        };
        var uploadResp = await client.SendAsync(uploadReq);
        uploadResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var sbomSummary = await uploadResp.Content.ReadFromJsonAsync<SbomDocumentSummaryDto>();
        sbomSummary.Should().NotBeNull();
        sbomSummary!.ComponentCount.Should().Be(2);

        // 4. Verify Project Dependencies API
        var depsResp = await client.GetAsync($"/api/v1/projects/{projectId}/sbom/dependencies");
        depsResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var deps = await depsResp.Content.ReadFromJsonAsync<List<ProjectDependencyDto>>();
        deps.Should().NotBeNull();
        deps!.Should().HaveCount(2);
        deps.Should().Contain(d => d.PackageName == "lodash" && d.Version == "4.17.20");
        deps.Should().Contain(d => d.PackageName == "requests" && d.Version == "2.25.0");

        // 5. Execute Fast SBOM Re-scan (< 2.5s, no source code scanning!)
        var rescanResp = await client.PostAsync($"/api/v1/projects/{projectId}/sbom/rescan", null);
        rescanResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var rescanResult = await rescanResp.Content.ReadFromJsonAsync<SbomRescanResultDto>();
        rescanResult.Should().NotBeNull();
        rescanResult!.DurationMs.Should().BeLessThan(3000, "Fast SBOM rescan must complete in seconds");
        rescanResult.VulnerabilitiesFoundCount.Should().BeGreaterThan(0, "Must detect lodash and/or requests vulnerabilities from seeded database");
        rescanResult.SuppressedByVexCount.Should().Be(0, "No VEX statements registered yet");

        // Verify finding was generated
        var findingsResp = await client.GetAsync($"/api/v1/findings?projectId={projectId}");
        var findingsContent = await findingsResp.Content.ReadAsStringAsync();
        findingsResp.StatusCode.Should().Be(HttpStatusCode.OK, $"GET findings returned: {findingsContent}");
        var findings = await findingsResp.Content.ReadFromJsonAsync<PagedResult<FindingSummaryDto>>();
        findings.Should().NotBeNull();
        findings!.Items.Should().Contain(f => f.CveId == "CVE-2021-23337", $"findings items: {findingsContent}");

        var lodashFinding = findings.Items.First(f => f.CveId == "CVE-2021-23337");
        lodashFinding.Status.Should().Be(FindingStatus.Open);

        // 6. Register OpenVEX statement: NotAffected
        var vexReq = new RegisterVexStatementRequest
        {
            VulnerabilityId = "CVE-2021-23337",
            PackagePurl = "pkg:npm/lodash@4.17.20",
            Status = VexStatus.NotAffected,
            Justification = VexJustification.VulnerableCodeNotInExecutePath,
            ImpactStatement = "Lodash template compiler is not used on user-controlled input",
            ActionStatement = "No remediation needed for current release",
            Author = "Security Team"
        };

        var vexResp = await client.PostAsJsonAsync($"/api/v1/projects/{projectId}/vex", vexReq);
        vexResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var vexResult = await vexResp.Content.ReadFromJsonAsync<VexStatementDto>();
        vexResult.Should().NotBeNull();
        vexResult!.Status.Should().Be(VexStatus.NotAffected);

        // 7. Verify Finding Status Transition to RiskAccepted via OpenVEX
        var detailResp = await client.GetAsync($"/api/v1/findings/{lodashFinding.Id}");
        var detail = await detailResp.Content.ReadFromJsonAsync<FindingDetailDto>();
        detail.Should().NotBeNull();
        detail!.Status.Should().Be(FindingStatus.RiskAccepted, "OpenVEX not_affected statement must transition finding to RiskAccepted");
        detail.StatusHistory.Should().Contain(h => h.ToStatus == FindingStatus.RiskAccepted && h.Reason!.Contains("OpenVEX not_affected"));

        // 8. Re-run Fast SBOM Re-scan: Now it must count as SuppressedByVexCount!
        var rescanResp2 = await client.PostAsync($"/api/v1/projects/{projectId}/sbom/rescan", null);
        rescanResp2.StatusCode.Should().Be(HttpStatusCode.OK);
        var rescanResult2 = await rescanResp2.Content.ReadFromJsonAsync<SbomRescanResultDto>();
        rescanResult2.Should().NotBeNull();
        rescanResult2!.SuppressedByVexCount.Should().BeGreaterOrEqualTo(1, "VEX statement must suppress the vulnerability in rescan");
    }

    private async Task<string> AuthenticateTenantAdminAsync(HttpClient client)
    {
        var loginResponse = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest
        {
            Email = "admin@tenant-alpha.local",
            Password = "AdminPassword123!"
        });

        loginResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var loginResult = await loginResponse.Content.ReadFromJsonAsync<LoginResponse>();
        return loginResult!.AccessToken;
    }

    private async Task<Guid> TriggerAndProcessScanAsync(HttpClient client, Guid projectId, string repoPath)
    {
        var scanReq = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/projects/{projectId}/scans")
        {
            Content = JsonContent.Create(new StartScanRequest
            {
                TargetBranch = "main",
                TargetDirectory = repoPath,
                Scanners = new[] { "native" }
            })
        };

        var startScanResp = await client.SendAsync(scanReq);
        startScanResp.StatusCode.Should().Be(HttpStatusCode.Accepted);
        var scan = await startScanResp.Content.ReadFromJsonAsync<ScanDto>();
        var scanId = scan!.Id;

        // Process Job via Worker
        using (var scope = _factory.Services.CreateScope())
        {
            var queue = scope.ServiceProvider.GetRequiredService<IJobQueueProvider>();
            var executionService = scope.ServiceProvider.GetRequiredService<ScanExecutionService>();

            while (true)
            {
                var job = await queue.DequeueJobAsync("m2-test-worker");
                if (job == null) break;

                await executionService.ProcessJobAsync(job, "m2-test-worker");
                if (job.ScanId == scanId) break;
            }
        }

        return scanId;
    }

    private static string ResolveSampleRepoPath()
    {
        var currentDir = Directory.GetCurrentDirectory();
        var searchDir = currentDir;
        while (!Directory.Exists(Path.Combine(searchDir, "samples", "sample-vulnerable-repo")) &&
               Directory.GetParent(searchDir) != null)
        {
            searchDir = Directory.GetParent(searchDir)!.FullName;
        }

        return Path.GetFullPath(Path.Combine(searchDir, "samples", "sample-vulnerable-repo"));
    }

    private static string ResolveSampleSbomPath()
    {
        var currentDir = Directory.GetCurrentDirectory();
        var searchDir = currentDir;
        while (!File.Exists(Path.Combine(searchDir, "samples", "sample-sbom", "cyclonedx.json")) &&
               Directory.GetParent(searchDir) != null)
        {
            searchDir = Directory.GetParent(searchDir)!.FullName;
        }

        return Path.GetFullPath(Path.Combine(searchDir, "samples", "sample-sbom", "cyclonedx.json"));
    }

    private static void CopyDirectory(string sourceDir, string targetDir)
    {
        Directory.CreateDirectory(targetDir);

        foreach (var file in Directory.GetFiles(sourceDir, "*.*", SearchOption.AllDirectories))
        {
            var relativePath = Path.GetRelativePath(sourceDir, file);
            var destPath = Path.Combine(targetDir, relativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(destPath)!);
            File.Copy(file, destPath, true);
        }
    }
}
