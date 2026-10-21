using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using PktSecurity.Application.Common.Interfaces;
using PktSecurity.Application.DTOs;
using PktSecurity.Domain.Entities;
using PktSecurity.Domain.Enums;
using PktSecurity.Infrastructure.Data;
using Xunit;

namespace PktSecurity.IntegrationTests;

public class AuditRegressionTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public AuditRegressionTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }

    private async Task<string> AuthenticateUserAsync(HttpClient client, string email, string password)
    {
        var resp = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest { Email = email, Password = password });
        resp.EnsureSuccessStatusCode();
        var doc = await resp.Content.ReadFromJsonAsync<LoginResponse>();
        return doc!.AccessToken;
    }

    [Fact]
    public async Task SEC001_Approving_Unverified_Remediation_Must_Return_BadRequest_400()
    {
        var client = _factory.CreateClient();

        // 1. Authenticate as SecurityEngineer
        var secToken = await AuthenticateUserAsync(client, "seceng@tenant-alpha.local", "SecEngPassword123!");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", secToken);

        // 2. Fetch project findings
        var findingsResp = await client.GetAsync("/api/v1/findings?limit=10");
        findingsResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var findingsPage = await findingsResp.Content.ReadFromJsonAsync<PagedResult<FindingSummaryDto>>();
        findingsPage!.Items.Should().NotBeEmpty();

        var targetFinding = findingsPage.Items.First();

        // 3. Generate remediation (Rule-based)
        var genResp = await client.PostAsync($"/api/v1/findings/{targetFinding.Id}/remediate", null);
        genResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var remediation = await genResp.Content.ReadFromJsonAsync<RemediationDto>();
        remediation.Should().NotBeNull();
        remediation!.VerificationStatus.Should().Be(RemediationVerificationStatus.Pending);

        // 4. Attempt to approve WITHOUT prior sandbox verification
        var approveResp = await client.PostAsync($"/api/v1/remediations/{remediation.Id}/approve", null);

        // Must fail with 400 Bad Request
        approveResp.StatusCode.Should().Be(HttpStatusCode.BadRequest,
            "Approval must be rejected if remediation is unverified (SEC-001 fix)");

        var errorBody = await approveResp.Content.ReadAsStringAsync();
        errorBody.Should().Contain("VerifiedFixed", "Error message must indicate VerifiedFixed prerequisite");
    }

    [Fact]
    public async Task SEC004_AuditEndpoints_Must_Deny_Developer_Role_With_Forbidden_403()
    {
        var client = _factory.CreateClient();

        // 1. Authenticate as Developer
        var devToken = await AuthenticateUserAsync(client, "dev@tenant-alpha.local", "DevPassword123!");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", devToken);

        // Developer attempts to access audit events
        var devAuditResp = await client.GetAsync("/api/v1/audit-events");
        devAuditResp.StatusCode.Should().Be(HttpStatusCode.Forbidden,
            "Developers must not be allowed to inspect audit events (SEC-004 fix)");

        // Developer attempts to verify audit chain
        var devVerifyResp = await client.GetAsync("/api/v1/audit-events/verify");
        devVerifyResp.StatusCode.Should().Be(HttpStatusCode.Forbidden,
            "Developers must not be allowed to verify audit chain (SEC-004 fix)");

        // 2. Authenticate as Auditor
        var auditorToken = await AuthenticateUserAsync(client, "auditor@tenant-alpha.local", "AuditorPassword123!");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", auditorToken);

        var auditorAuditResp = await client.GetAsync("/api/v1/audit-events");
        auditorAuditResp.StatusCode.Should().Be(HttpStatusCode.OK, "Auditors must be allowed to inspect audit events");

        var auditorVerifyResp = await client.GetAsync("/api/v1/audit-events/verify");
        auditorVerifyResp.StatusCode.Should().Be(HttpStatusCode.OK, "Auditors must be allowed to verify audit chain");
    }

    [Fact]
    public async Task SEC002_DeadLetter_Queue_Reaps_Expired_MaxAttempt_Jobs_And_Fails_Scan()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var queue = scope.ServiceProvider.GetRequiredService<IJobQueueProvider>();

        var tenantId = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");

        var connStr = db.Database.GetConnectionString()!;
        await using var conn = new NpgsqlConnection(connStr);
        await conn.OpenAsync();
        await conn.ExecuteAsync("SELECT set_config('app.current_tenant_id', '', false);");

        var projectId = await conn.QueryFirstOrDefaultAsync<Guid>(
            "SELECT id FROM projects WHERE tenant_id = @tenantId LIMIT 1;", new { tenantId });
        if (projectId == Guid.Empty)
        {
            projectId = Guid.NewGuid();
            await conn.ExecuteAsync(@"
                INSERT INTO projects (id, tenant_id, name, description, business_criticality, is_internet_facing, data_sensitivity, created_at)
                VALUES (@projectId, @tenantId, 'DeadLetter Test Project', 'Test', 0, false, 'Internal', NOW());
            ", new { projectId, tenantId });
        }

        var scanId = Guid.NewGuid();
        var jobId = Guid.NewGuid();

        await conn.ExecuteAsync(@"
            INSERT INTO scans (id, tenant_id, project_id, status, target_branch, created_at)
            VALUES (@scanId, @tenantId, @projectId, @runningStatus, 'main', NOW() - INTERVAL '1 hour');
        ", new { scanId, tenantId, projectId, runningStatus = (int)ScanStatus.Running });

        await conn.ExecuteAsync(@"
            INSERT INTO scan_jobs (
                id, tenant_id, scan_id, scanner_name, status, priority, 
                lease_owner, leased_until, heartbeat_at, attempt_count, max_attempts, 
                cancel_requested, created_at, started_at
            )
            VALUES (
                @jobId, @tenantId, @scanId, 'trivy', @runningStatus, 100,
                'crashed-worker', NOW() - INTERVAL '10 minutes', NOW() - INTERVAL '10 minutes', 3, 3,
                false, NOW() - INTERVAL '1 hour', NOW() - INTERVAL '10 minutes'
            );
        ", new { jobId, tenantId, scanId, runningStatus = (int)ScanJobStatus.Running });

        // Act: Trigger DequeueJobAsync (which executes the DeadLetter reaper)
        var dequeued = await queue.DequeueJobAsync("active-worker");

        // Assert: Job should be DeadLettered (Status = Failed)
        var deadJobStatus = await conn.QuerySingleAsync<int>("SELECT status FROM scan_jobs WHERE id = @jobId;", new { jobId });
        deadJobStatus.Should().Be((int)ScanJobStatus.Failed, "Expired job with max attempts must be DeadLettered to Failed");

        var deadScanStatus = await conn.QuerySingleAsync<int>("SELECT status FROM scans WHERE id = @scanId;", new { scanId });
        deadScanStatus.Should().Be((int)ScanStatus.Failed, "Parent scan of DeadLettered job must transition to Failed");

        // Clean up
        await conn.ExecuteAsync("DELETE FROM scan_jobs WHERE id = @jobId; DELETE FROM scans WHERE id = @scanId;", new { jobId, scanId });
    }
}
