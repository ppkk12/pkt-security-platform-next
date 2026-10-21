using Dapper;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using PktSecurity.Domain.Entities;
using PktSecurity.Domain.Enums;
using PktSecurity.Infrastructure.Data;
using Xunit;

namespace PktSecurity.IntegrationTests;

public class PostgresRlsIsolationTests
{
    private const string AdminConnectionString = "Host=localhost;Port=5432;Database=pktsecurity;Username=postgres;Password=postgres";
    private const string AppUserConnectionString = "Host=localhost;Port=5432;Database=pktsecurity;Username=app_user;Password=app_password";

    static PostgresRlsIsolationTests()
    {
        Dapper.DefaultTypeMap.MatchNamesWithUnderscores = true;
    }

    [Fact]
    public async Task PostgresRls_MustEnforceStrictTenantDataIsolation()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseNpgsql(AdminConnectionString)
            .Options;

        await using (var db = new AppDbContext(options))
        {
            await DatabaseInitializer.InitializeDatabaseAsync(db);
        }

        var tenantA = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        var tenantB = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");

        // 1. Seed test projects for Tenant A and Tenant B
        await using (var seedConn = new NpgsqlConnection(AdminConnectionString))
        {
            await seedConn.OpenAsync();

            // Set context to Tenant A and insert Tenant A project & finding
            await seedConn.ExecuteAsync("SELECT set_config('app.current_tenant_id', @tenantA, false);", new { tenantA = tenantA.ToString() });
            var projectAId = Guid.NewGuid();
            var findingAId = Guid.NewGuid();

            await seedConn.ExecuteAsync(@"
                INSERT INTO projects (id, tenant_id, name, business_criticality, is_internet_facing, data_sensitivity, created_at)
                VALUES (@projectAId, @tenantA, 'Project Alpha', 1, false, 'Internal', NOW());

                INSERT INTO findings (id, tenant_id, project_id, title, description, severity, risk_score, confidence, status, category, scanner_name, primary_fingerprint, secondary_fingerprint, occurrence_count, first_seen_scan_id, last_seen_scan_id, reachability, is_kev, created_at, updated_at)
                VALUES (@findingAId, @tenantA, @projectAId, 'Tenant A Secret Leak', 'Desc', 4, 90.0, 1.0, 0, 2, 'native', 'fp_a1', 'fp_a2', 1, @findingAId, @findingAId, 3, false, NOW(), NOW());
            ", new { projectAId, findingAId, tenantA });

            // Set context to Tenant B and insert Tenant B project & finding
            await seedConn.ExecuteAsync("SELECT set_config('app.current_tenant_id', @tenantB, false);", new { tenantB = tenantB.ToString() });
            var projectBId = Guid.NewGuid();
            var findingBId = Guid.NewGuid();

            await seedConn.ExecuteAsync(@"
                INSERT INTO projects (id, tenant_id, name, business_criticality, is_internet_facing, data_sensitivity, created_at)
                VALUES (@projectBId, @tenantB, 'Project Beta', 1, false, 'Internal', NOW());

                INSERT INTO findings (id, tenant_id, project_id, title, description, severity, risk_score, confidence, status, category, scanner_name, primary_fingerprint, secondary_fingerprint, occurrence_count, first_seen_scan_id, last_seen_scan_id, reachability, is_kev, created_at, updated_at)
                VALUES (@findingBId, @tenantB, @projectBId, 'Tenant B Vulnerability', 'Desc', 3, 75.0, 1.0, 0, 0, 'native', 'fp_b1', 'fp_b2', 1, @findingBId, @findingBId, 2, false, NOW(), NOW());
            ", new { projectBId, findingBId, tenantB });
        }

        // 2. Query as Tenant A via raw SQL without any WHERE clause
        await using (var connA = new NpgsqlConnection(AppUserConnectionString))
        {
            await connA.OpenAsync();
            await connA.ExecuteAsync("SELECT set_config('app.current_tenant_id', @tenantA, false);", new { tenantA = tenantA.ToString() });

            // Even with "SELECT * FROM findings" without WHERE, PostgreSQL RLS MUST filter out Tenant B
            var findingsForA = (await connA.QueryAsync<Finding>("SELECT * FROM findings;")).ToList();

            findingsForA.Should().NotBeEmpty();
            findingsForA.Should().OnlyContain(f => f.TenantId == tenantA, "PostgreSQL RLS must strictly block Tenant B findings from Tenant A");
            findingsForA.Should().NotContain(f => f.TenantId == tenantB);

            // Verify cross-tenant write/insert block by RLS WITH CHECK policy
            var illegalFindingId = Guid.NewGuid();
            var insertAction = async () =>
            {
                await connA.ExecuteAsync(@"
                    INSERT INTO findings (id, tenant_id, project_id, title, description, severity, risk_score, confidence, status, category, scanner_name, primary_fingerprint, secondary_fingerprint, occurrence_count, first_seen_scan_id, last_seen_scan_id, reachability, is_kev, created_at, updated_at)
                    VALUES (@illegalFindingId, @tenantB, @illegalFindingId, 'Illegal Finding Injection', 'Desc', 1, 10.0, 1.0, 0, 0, 'native', 'fp_illegal', 'fp_illegal2', 1, @illegalFindingId, @illegalFindingId, 0, false, NOW(), NOW());
                ", new { illegalFindingId, tenantB });
            };

            await insertAction.Should().ThrowAsync<PostgresException>("Inserting data with another tenant_id must violate RLS WITH CHECK policy")
                .Where(e => e.SqlState == "42501"); // 42501 is insufficient_privilege (PostgreSQL RLS violation)
        }

        // 3. Query as Tenant B via raw SQL
        await using (var connB = new NpgsqlConnection(AppUserConnectionString))
        {
            await connB.OpenAsync();
            await connB.ExecuteAsync("SELECT set_config('app.current_tenant_id', @tenantB, false);", new { tenantB = tenantB.ToString() });

            var findingsForB = (await connB.QueryAsync<Finding>("SELECT * FROM findings;")).ToList();

            findingsForB.Should().NotBeEmpty();
            findingsForB.Should().OnlyContain(f => f.TenantId == tenantB, "PostgreSQL RLS must strictly block Tenant A findings from Tenant B");
            findingsForB.Should().NotContain(f => f.TenantId == tenantA);
        }

        // 4. Query with NO tenant session set
        await using (var emptyConn = new NpgsqlConnection(AppUserConnectionString))
        {
            await emptyConn.OpenAsync();
            await emptyConn.ExecuteAsync("SELECT set_config('app.current_tenant_id', '', false);");

            var noTenantFindings = (await emptyConn.QueryAsync<Finding>("SELECT * FROM findings;")).ToList();
            noTenantFindings.Should().BeEmpty("When app.current_tenant_id is empty, RLS must return 0 rows for safety");
        }
    }
}
