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

public class EndToEndVerticalSliceTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public EndToEndVerticalSliceTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task FullVerticalSlice_FromScanToExport_MustSucceedDeterministically()
    {
        var client = _factory.CreateClient();

        // 1. Authenticate as Tenant Admin
        var loginResponse = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest
        {
            Email = "admin@tenant-alpha.local",
            Password = "AdminPassword123!"
        });

        loginResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var loginResult = await loginResponse.Content.ReadFromJsonAsync<LoginResponse>();
        loginResult.Should().NotBeNull();
        loginResult!.AccessToken.Should().NotBeNullOrWhiteSpace();

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", loginResult.AccessToken);

        // 2. Resolve sample-vulnerable-repo path
        var currentDir = Directory.GetCurrentDirectory();
        // Traverse upwards until we find samples/sample-vulnerable-repo
        var searchDir = currentDir;
        while (!Directory.Exists(Path.Combine(searchDir, "samples", "sample-vulnerable-repo")) &&
               Directory.GetParent(searchDir) != null)
        {
            searchDir = Directory.GetParent(searchDir)!.FullName;
        }

        var sampleRepoPath = Path.GetFullPath(Path.Combine(searchDir, "samples", "sample-vulnerable-repo"));
        Directory.Exists(sampleRepoPath).Should().BeTrue($"Sample repo must exist at {sampleRepoPath}");

        // 3. Create Project pointing to sample repo
        var createProjectResp = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest
        {
            Name = $"E2E Project {Guid.NewGuid():N}",
            Description = "Automated E2E Verification Project",
            BusinessCriticality = BusinessCriticality.High,
            IsInternetFacing = true,
            DataSensitivity = "Confidential",
            RepositoryUrl = sampleRepoPath
        });

        createProjectResp.StatusCode.Should().Be(HttpStatusCode.Created);
        var project = await createProjectResp.Content.ReadFromJsonAsync<ProjectDto>();
        project.Should().NotBeNull();
        var projectId = project!.Id;

        // 4. Trigger Scan with Idempotency-Key
        var idempotencyKey = $"idem-{Guid.NewGuid():N}";
        var scanReq = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/projects/{projectId}/scans")
        {
            Content = JsonContent.Create(new StartScanRequest
            {
                TargetBranch = "main",
                TargetDirectory = sampleRepoPath,
                Scanners = new[] { "native" }
            })
        };
        scanReq.Headers.Add("Idempotency-Key", idempotencyKey);

        var startScanResp = await client.SendAsync(scanReq);
        startScanResp.StatusCode.Should().Be(HttpStatusCode.Accepted);
        var scan = await startScanResp.Content.ReadFromJsonAsync<ScanDto>();
        scan.Should().NotBeNull();
        var scanId = scan!.Id;

        // Verify Idempotency: second request with same key returns existing scan
        var scanReqDuplicate = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/projects/{projectId}/scans")
        {
            Content = JsonContent.Create(new StartScanRequest
            {
                TargetBranch = "main",
                TargetDirectory = sampleRepoPath
            })
        };
        scanReqDuplicate.Headers.Add("Idempotency-Key", idempotencyKey);

        var dupResp = await client.SendAsync(scanReqDuplicate);
        dupResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var dupScan = await dupResp.Content.ReadFromJsonAsync<ScanDto>();
        dupScan!.Id.Should().Be(scanId, "Idempotency-Key must prevent duplicate scan creation");

        // 5. Worker Lease & Execute Scan Job
        using (var scope = _factory.Services.CreateScope())
        {
            var queue = scope.ServiceProvider.GetRequiredService<IJobQueueProvider>();
            var executionService = scope.ServiceProvider.GetRequiredService<ScanExecutionService>();

            ScanJob? targetJob = null;
            while (true)
            {
                var job = await queue.DequeueJobAsync("test-worker-runner");
                if (job == null) break;

                await executionService.ProcessJobAsync(job, "test-worker-runner");
                if (job.ScanId == scanId)
                {
                    targetJob = job;
                    break;
                }
            }

            targetJob.Should().NotBeNull("ScanJob for the test scan must be dequeued and processed");
        }

        // 6. Verify Scan status is Completed
        var checkScanResp = await client.GetAsync($"/api/v1/scans/{scanId}");
        checkScanResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var completedScan = await checkScanResp.Content.ReadFromJsonAsync<ScanDto>();
        completedScan!.Status.Should().Be(ScanStatus.Completed);

        // 7. Keyset Pagination on Findings List
        var findingsPage1Resp = await client.GetAsync($"/api/v1/findings?projectId={projectId}&limit=2");
        findingsPage1Resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var page1 = await findingsPage1Resp.Content.ReadFromJsonAsync<PagedResult<FindingSummaryDto>>();
        page1.Should().NotBeNull();
        page1!.Items.Should().HaveCount(2);
        page1.HasMore.Should().BeTrue();
        page1.NextCursor.Should().NotBeNullOrWhiteSpace();

        // Fetch page 2 using cursor
        var findingsPage2Resp = await client.GetAsync($"/api/v1/findings?projectId={projectId}&cursor={Uri.EscapeDataString(page1.NextCursor!)}&limit=10");
        findingsPage2Resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var page2 = await findingsPage2Resp.Content.ReadFromJsonAsync<PagedResult<FindingSummaryDto>>();
        page2.Should().NotBeNull();
        page2!.Items.Should().NotBeEmpty();

        var allFindings = page1.Items.Concat(page2.Items).ToList();
        allFindings.Should().Contain(f => f.Category == FindingCategory.SAST && f.CweId == "CWE-89", "Must detect SQL Injection");
        allFindings.Should().Contain(f => f.Category == FindingCategory.SAST && f.CweId == "CWE-78", "Must detect Command Injection");
        allFindings.Should().Contain(f => f.Category == FindingCategory.Secret, "Must detect dummy secrets");
        allFindings.Should().Contain(f => f.Category == FindingCategory.SCA && f.CveId == "CVE-2021-23337", "Must detect vulnerable lodash SCA dependency");

        // 8. Finding Detail View
        var sampleFinding = allFindings.First();
        var detailResp = await client.GetAsync($"/api/v1/findings/{sampleFinding.Id}");
        detailResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var detail = await detailResp.Content.ReadFromJsonAsync<FindingDetailDto>();
        detail.Should().NotBeNull();
        detail!.Id.Should().Be(sampleFinding.Id);
        detail.Evidences.Should().NotBeEmpty();
        detail.Evidences.First().CodeSnippetRedacted.Should().NotBeNullOrWhiteSpace();

        // 9. Triage Status Update
        var patchResp = await client.PatchAsJsonAsync($"/api/v1/findings/{sampleFinding.Id}/status", new
        {
            status = FindingStatus.Confirmed,
            reason = "Verified in code review"
        });
        patchResp.StatusCode.Should().Be(HttpStatusCode.OK);

        // 10. Export in JSON, CSV, SARIF
        var exportJsonResp = await client.GetAsync($"/api/v1/projects/{projectId}/export?format=json");
        exportJsonResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var jsonContent = await exportJsonResp.Content.ReadAsStringAsync();
        jsonContent.Should().Contain("CWE-89");

        var exportCsvResp = await client.GetAsync($"/api/v1/projects/{projectId}/export?format=csv");
        exportCsvResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var csvContent = await exportCsvResp.Content.ReadAsStringAsync();
        csvContent.Should().StartWith("FindingId,ProjectId,Title");
        csvContent.Should().Contain("CWE-89");

        var exportSarifResp = await client.GetAsync($"/api/v1/projects/{projectId}/export?format=sarif");
        exportSarifResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var sarifContent = await exportSarifResp.Content.ReadAsStringAsync();
        sarifContent.Should().Contain("\"version\": \"2.1.0\"");
        sarifContent.Should().Contain("PktSecurityPlatform");

        // 11. RBAC Tests: Auditor role is strictly read-only
        var auditorLoginResp = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest
        {
            Email = "auditor@tenant-alpha.local",
            Password = "AuditorPassword123!"
        });
        var auditorLogin = await auditorLoginResp.Content.ReadFromJsonAsync<LoginResponse>();
        var auditorClient = _factory.CreateClient();
        auditorClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", auditorLogin!.AccessToken);

        var auditorCreateProjResp = await auditorClient.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest { Name = "Illegal" });
        auditorCreateProjResp.StatusCode.Should().Be(HttpStatusCode.Forbidden, "Auditor role must not be allowed to create projects");

        var auditorScanResp = await auditorClient.PostAsJsonAsync($"/api/v1/projects/{projectId}/scans", new StartScanRequest());
        auditorScanResp.StatusCode.Should().Be(HttpStatusCode.Forbidden, "Auditor role must not be allowed to trigger scans");

        var auditorTriageResp = await auditorClient.PatchAsJsonAsync($"/api/v1/findings/{sampleFinding.Id}/status", new
        {
            status = FindingStatus.Confirmed
        });
        auditorTriageResp.StatusCode.Should().Be(HttpStatusCode.Forbidden, "Auditor role must not be allowed to mutate finding statuses");

        // 12. RBAC Tests: Developer role cannot approve RiskAccepted
        var devLoginResp = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest
        {
            Email = "dev@tenant-alpha.local",
            Password = "DevPassword123!"
        });
        var devLogin = await devLoginResp.Content.ReadFromJsonAsync<LoginResponse>();
        var devClient = _factory.CreateClient();
        devClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", devLogin!.AccessToken);

        var devRiskAcceptResp = await devClient.PatchAsJsonAsync($"/api/v1/findings/{sampleFinding.Id}/status", new
        {
            status = FindingStatus.RiskAccepted,
            reason = "Developer trying to accept risk"
        });
        devRiskAcceptResp.StatusCode.Should().Be(HttpStatusCode.Forbidden, "Developers cannot approve RiskAccepted status");
    }
}
