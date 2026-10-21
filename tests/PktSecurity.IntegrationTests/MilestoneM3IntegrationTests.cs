using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using PktSecurity.Application.DTOs;
using PktSecurity.Domain.Enums;
using PktSecurity.Infrastructure.Data;
using Xunit;

namespace PktSecurity.IntegrationTests;

public class MilestoneM3IntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public MilestoneM3IntegrationTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task M3_AiRemediation_Generate_VerifyInSandbox_And_HumanInTheLoopApproval_MustWorkCorrectly()
    {
        var client = _factory.CreateClient();

        // 1. Authenticate as Tenant Admin
        var adminToken = await AuthenticateUserAsync(client, "admin@tenant-alpha.local", "AdminPassword123!");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);

        // 2. Resolve sample-vulnerable-repo path
        var currentDir = Directory.GetCurrentDirectory();
        var searchDir = currentDir;
        while (!Directory.Exists(Path.Combine(searchDir, "samples", "sample-vulnerable-repo")) &&
               Directory.GetParent(searchDir) != null)
        {
            searchDir = Directory.GetParent(searchDir)!.FullName;
        }
        var sampleRepoPath = Path.GetFullPath(Path.Combine(searchDir, "samples", "sample-vulnerable-repo"));
        Directory.Exists(sampleRepoPath).Should().BeTrue($"Sample repo must exist at {sampleRepoPath}");

        // Create Project
        var createProjResp = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest
        {
            Name = $"M3 Remediation Test {Guid.NewGuid():N}",
            Description = "AI Remediation and Sandboxed Verification Project",
            BusinessCriticality = BusinessCriticality.High,
            IsInternetFacing = true,
            DataSensitivity = "Confidential",
            RepositoryUrl = sampleRepoPath
        });
        createProjResp.StatusCode.Should().Be(HttpStatusCode.Created);
        var project = await createProjResp.Content.ReadFromJsonAsync<ProjectDto>();
        var projectId = project!.Id;

        // 3. Trigger Scan and process
        var startScanResp = await client.PostAsJsonAsync($"/api/v1/projects/{projectId}/scans", new StartScanRequest
        {
            TargetDirectory = sampleRepoPath,
            TargetBranch = "main",
            Scanners = new[] { "native" }
        });
        startScanResp.StatusCode.Should().Be(HttpStatusCode.Accepted);
        var scan = await startScanResp.Content.ReadFromJsonAsync<ScanDto>();
        var scanId = scan!.Id;

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var executionService = scope.ServiceProvider.GetRequiredService<PktSecurity.Infrastructure.Services.ScanExecutionService>();
            var queue = scope.ServiceProvider.GetRequiredService<PktSecurity.Application.Common.Interfaces.IJobQueueProvider>();

            while (true)
            {
                var job = await queue.DequeueJobAsync("m3-test-worker");
                if (job == null) break;

                await executionService.ProcessJobAsync(job, "m3-test-worker");
                if (job.ScanId == scanId) break;
            }
        }

        // 4. Retrieve generated finding
        var findingsResp = await client.GetAsync($"/api/v1/findings?projectId={projectId}&limit=10");
        findingsResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var findings = await findingsResp.Content.ReadFromJsonAsync<PagedResult<FindingSummaryDto>>();
        findings.Should().NotBeNull();
        findings!.Items.Should().NotBeEmpty("Scan should have detected findings in sample repo");

        var targetFinding = findings.Items.First();

        // 5. Generate AI Remediation
        var remediateResp = await client.PostAsync($"/api/v1/findings/{targetFinding.Id}/remediate", null);
        remediateResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var remediation = await remediateResp.Content.ReadFromJsonAsync<RemediationDto>();
        remediation.Should().NotBeNull();
        remediation!.FindingId.Should().Be(targetFinding.Id);

        // Schema verification: verified_facts, ai_hypothesis_analysis, proposed_unified_diff, side_effects_warning
        remediation.VerifiedFacts.Should().NotBeEmpty("Must have objective verified facts");
        remediation.AiHypothesisAnalysis.Should().NotBeNullOrWhiteSpace("Must contain AI hypothesis/mechanism analysis");
        remediation.ProposedUnifiedDiff.Should().StartWith("--- ", "Must produce valid unified diff header");
        remediation.SideEffectsWarning.Should().NotBeNullOrWhiteSpace("Must contain side effects and testing warning");
        remediation.VerificationStatus.Should().Be(RemediationVerificationStatus.Pending);
        remediation.ApprovalStatus.Should().Be(RemediationApprovalStatus.PendingReview);

        // 6. Verify Remediation in Sandbox
        var verifyResp = await client.PostAsync($"/api/v1/remediations/{remediation.Id}/verify", null);
        verifyResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var verifyResult = await verifyResp.Content.ReadFromJsonAsync<RemediationVerificationResultDto>();
        verifyResult.Should().NotBeNull();
        verifyResult!.RemediationId.Should().Be(remediation.Id);
        verifyResult.VerificationStatus.Should().Be(RemediationVerificationStatus.VerifiedFixed,
            "Rule-based remediation applied to sandbox should eliminate the vulnerability on re-scan");
        verifyResult.DurationMs.Should().BeGreaterThan(0);

        // 7. Human-in-the-Loop RBAC control: Developer cannot approve remediation
        var devToken = await AuthenticateUserAsync(client, "dev@tenant-alpha.local", "DevPassword123!");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", devToken);

        var devApproveResp = await client.PostAsync($"/api/v1/remediations/{remediation.Id}/approve", null);
        devApproveResp.StatusCode.Should().Be(HttpStatusCode.Forbidden, "Developers cannot approve security remediations");

        // 8. Human-in-the-Loop RBAC control: Auditor cannot approve
        var auditorToken = await AuthenticateUserAsync(client, "auditor@tenant-alpha.local", "AuditorPassword123!");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", auditorToken);

        var auditorApproveResp = await client.PostAsync($"/api/v1/remediations/{remediation.Id}/approve", null);
        auditorApproveResp.StatusCode.Should().Be(HttpStatusCode.Forbidden, "Auditors cannot approve security remediations");

        // 9. SecurityEngineer approves remediation
        var secEngToken = await AuthenticateUserAsync(client, "seceng@tenant-alpha.local", "SecEngPassword123!");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", secEngToken);

        var secEngApproveResp = await client.PostAsync($"/api/v1/remediations/{remediation.Id}/approve", null);
        secEngApproveResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var approvedRemediation = await secEngApproveResp.Content.ReadFromJsonAsync<RemediationDto>();
        approvedRemediation.Should().NotBeNull();
        approvedRemediation!.ApprovalStatus.Should().Be(RemediationApprovalStatus.Approved);
        approvedRemediation.ApprovedByUserId.Should().NotBeNull();
        approvedRemediation.ApprovedAt.Should().NotBeNull();

        // 10. Verify Finding Status is now Remediated
        var findingDetailResp = await client.GetAsync($"/api/v1/findings/{targetFinding.Id}");
        findingDetailResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var findingDetail = await findingDetailResp.Content.ReadFromJsonAsync<FindingDetailDto>();
        findingDetail!.Status.Should().Be(FindingStatus.Remediated, "Approved remediation should transition finding to Remediated status");
    }

    [Fact]
    public async Task M3_AuditLog_HashChain_And_DirectDatabaseTamperDetection_MustBeDetected()
    {
        var client = _factory.CreateClient();

        // 0. Ensure clean audit log state for test
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            await db.Database.ExecuteSqlRawAsync("TRUNCATE TABLE audit_events CASCADE;");
        }

        // 1. Authenticate as Tenant Admin
        var adminToken = await AuthenticateUserAsync(client, "admin@tenant-alpha.local", "AdminPassword123!");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);

        // 2. Perform actions to generate chained audit events
        await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest
        {
            Name = $"Audit Test Project {Guid.NewGuid():N}",
            Description = "Audit log test",
            BusinessCriticality = BusinessCriticality.Low,
            IsInternetFacing = false,
            DataSensitivity = "Internal"
        });

        // 3. Verify clean hash chain
        var verifyResp1 = await client.GetAsync("/api/v1/audit-events/verify");
        verifyResp1.StatusCode.Should().Be(HttpStatusCode.OK);
        var verifyResult1 = await verifyResp1.Content.ReadFromJsonAsync<AuditVerificationResultDto>();
        verifyResult1.Should().NotBeNull();
        verifyResult1!.IsValid.Should().BeTrue($"Clean audit events must pass hash chain verification but failed with: {verifyResult1.BrokenReason}");
        verifyResult1.TotalEvents.Should().BeGreaterThan(0);

        // 4. Directly modify an audit record in the database behind the back of the application
        Guid tamperedEventId;
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"SELECT set_config('app.current_tenant_id', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', false);");

            var targetEvent = await db.AuditEvents.OrderByDescending(e => e.CreatedAt).FirstAsync();
            tamperedEventId = targetEvent.Id;

            // Direct SQL tamper of payload without updating event_hash
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"UPDATE audit_events SET action = 'tampered_malicious_action' WHERE id = {targetEvent.Id};");
        }

        // 5. Re-verify hash chain: MUST detect tamper!
        var verifyResp2 = await client.GetAsync("/api/v1/audit-events/verify");
        verifyResp2.StatusCode.Should().Be(HttpStatusCode.OK);
        var verifyResult2 = await verifyResp2.Content.ReadFromJsonAsync<AuditVerificationResultDto>();
        verifyResult2.Should().NotBeNull();
        verifyResult2!.IsValid.Should().BeFalse("Direct database modification must break hash chain verification");
        verifyResult2.BrokenEventId.Should().Be(tamperedEventId);
        verifyResult2.BrokenReason.Should().Contain("Tampered payload detected");
    }

    private static async Task<string> AuthenticateUserAsync(HttpClient client, string email, string password)
    {
        var loginResponse = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest
        {
            Email = email,
            Password = password
        });

        loginResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var loginResult = await loginResponse.Content.ReadFromJsonAsync<LoginResponse>();
        loginResult.Should().NotBeNull();
        return loginResult!.AccessToken;
    }
}
