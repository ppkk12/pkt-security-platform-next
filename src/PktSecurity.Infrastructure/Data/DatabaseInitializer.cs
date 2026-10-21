using Microsoft.EntityFrameworkCore;
using PktSecurity.Domain.Entities;
using PktSecurity.Domain.Enums;
using PktSecurity.Infrastructure.Security;

namespace PktSecurity.Infrastructure.Data;

public static class DatabaseInitializer
{
    private static readonly string[] TenantTables =
    {
        "users",
        "api_keys",
        "projects",
        "repositories",
        "scans",
        "scan_jobs",
        "findings",
        "finding_evidences",
        "finding_status_history",
        "audit_events",
        "risk_assessments",
        "sbom_documents",
        "project_dependencies",
        "vex_statements",
        "remediations"
    };

    public static async Task InitializeDatabaseAsync(AppDbContext context)
    {
        await context.Database.EnsureCreatedAsync();
        await EnsureMissingTablesCreatedAsync(context);
        await EnableRowLevelSecurityAsync(context);
        await EnsureAppUserRoleAsync(context);
        await SeedInitialDataAsync(context);
        await SeedVulnerabilitiesAsync(context);
    }

    private static async Task EnsureMissingTablesCreatedAsync(AppDbContext context)
    {
        var sql = @"
            ALTER TABLE findings ADD COLUMN IF NOT EXISTS correlation_group_id UUID;
            CREATE INDEX IF NOT EXISTS ix_findings_tenant_correlation ON findings(tenant_id, correlation_group_id);

            CREATE TABLE IF NOT EXISTS packages (
                id UUID PRIMARY KEY,
                purl TEXT NOT NULL,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                license TEXT,
                created_at TIMESTAMPTZ NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS ux_packages_purl ON packages(purl);

            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id UUID PRIMARY KEY,
                cve_id TEXT NOT NULL,
                summary TEXT NOT NULL,
                description TEXT NOT NULL,
                severity INT NOT NULL,
                cvss_score DOUBLE PRECISION,
                cwe_id TEXT,
                affected_purl_pattern TEXT NOT NULL,
                affected_version_range TEXT NOT NULL,
                fixed_version TEXT,
                is_kev BOOLEAN NOT NULL,
                epss_score DOUBLE PRECISION,
                created_at TIMESTAMPTZ NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS ux_vulnerabilities_cve_id ON vulnerabilities(cve_id);

            CREATE TABLE IF NOT EXISTS risk_assessments (
                id UUID PRIMARY KEY,
                tenant_id UUID NOT NULL,
                finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
                final_score DOUBLE PRECISION NOT NULL,
                base_severity_score DOUBLE PRECISION NOT NULL,
                threat_score DOUBLE PRECISION NOT NULL,
                reachability_score DOUBLE PRECISION NOT NULL,
                asset_multiplier DOUBLE PRECISION NOT NULL,
                formula_version TEXT NOT NULL,
                cvss_score DOUBLE PRECISION,
                is_kev BOOLEAN,
                epss_score DOUBLE PRECISION,
                reachability INT NOT NULL,
                missing_inputs_json TEXT NOT NULL,
                calculated_at TIMESTAMPTZ NOT NULL,
                created_at TIMESTAMPTZ NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_risk_assessments_tenant_finding ON risk_assessments(tenant_id, finding_id);

            CREATE TABLE IF NOT EXISTS sbom_documents (
                id UUID PRIMARY KEY,
                tenant_id UUID NOT NULL,
                project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                format TEXT NOT NULL,
                spec_version TEXT NOT NULL,
                serial_number TEXT,
                version INT NOT NULL,
                component_count INT NOT NULL,
                raw_json TEXT,
                created_at TIMESTAMPTZ NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_sbom_documents_tenant_project ON sbom_documents(tenant_id, project_id, created_at);

            CREATE TABLE IF NOT EXISTS project_dependencies (
                id UUID PRIMARY KEY,
                tenant_id UUID NOT NULL,
                project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                sbom_document_id UUID NOT NULL REFERENCES sbom_documents(id) ON DELETE CASCADE,
                package_id UUID NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
                package_purl TEXT NOT NULL,
                package_name TEXT NOT NULL,
                version TEXT NOT NULL,
                is_direct BOOLEAN NOT NULL,
                depth INT NOT NULL,
                dependency_path_json TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_project_dependencies_lookup ON project_dependencies(tenant_id, project_id, package_purl);

            CREATE TABLE IF NOT EXISTS vex_statements (
                id UUID PRIMARY KEY,
                tenant_id UUID NOT NULL,
                project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                vulnerability_id TEXT NOT NULL,
                package_purl TEXT,
                status INT NOT NULL,
                justification INT,
                impact_statement TEXT,
                action_statement TEXT,
                author TEXT,
                created_at TIMESTAMPTZ NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_vex_statements_lookup ON vex_statements(tenant_id, project_id, vulnerability_id);

            CREATE TABLE IF NOT EXISTS remediations (
                id UUID PRIMARY KEY,
                tenant_id UUID NOT NULL,
                finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
                verified_facts_json TEXT NOT NULL,
                ai_hypothesis_analysis TEXT NOT NULL,
                proposed_unified_diff TEXT NOT NULL,
                side_effects_warning TEXT NOT NULL,
                verification_status INT NOT NULL,
                verification_details TEXT,
                approval_status INT NOT NULL,
                approved_by_user_id UUID,
                approved_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_remediations_finding ON remediations(tenant_id, finding_id);
        ";

        await context.Database.ExecuteSqlRawAsync(sql);
    }

    private static async Task EnsureAppUserRoleAsync(AppDbContext context)
    {
        await context.Database.ExecuteSqlRawAsync(@"
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN
                    CREATE ROLE app_user WITH LOGIN PASSWORD 'app_password';
                END IF;
            END
            $$;
            GRANT ALL ON SCHEMA public TO app_user;
            GRANT ALL ON ALL TABLES IN SCHEMA public TO app_user;
            GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO app_user;
            ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO app_user;
            ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO app_user;
        ");
    }

    public static async Task EnableRowLevelSecurityAsync(AppDbContext context)
    {
        foreach (var table in TenantTables)
        {
            var sql = $@"
                ALTER TABLE ""{table}"" ENABLE ROW LEVEL SECURITY;
                ALTER TABLE ""{table}"" FORCE ROW LEVEL SECURITY;
                DROP POLICY IF EXISTS tenant_isolation_policy ON ""{table}"";
                CREATE POLICY tenant_isolation_policy ON ""{table}""
                    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
                    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
            ";

            await context.Database.ExecuteSqlRawAsync(sql);
        }
    }

    private static async Task SeedInitialDataAsync(AppDbContext context)
    {
        if (await context.Organizations.AnyAsync())
            return;

        var org = new Organization
        {
            Id = Guid.Parse("11111111-1111-1111-1111-111111111111"),
            Name = "PktSecurity Default Organization",
            CreatedAt = DateTime.UtcNow
        };
        context.Organizations.Add(org);

        var tenantA = new Tenant
        {
            Id = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            OrganizationId = org.Id,
            Name = "Tenant Alpha",
            CreatedAt = DateTime.UtcNow
        };
        var tenantB = new Tenant
        {
            Id = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            OrganizationId = org.Id,
            Name = "Tenant Beta",
            CreatedAt = DateTime.UtcNow
        };
        context.Tenants.AddRange(tenantA, tenantB);

        var adminUser = new User
        {
            Id = Guid.Parse("99999999-9999-9999-9999-999999999999"),
            TenantId = tenantA.Id,
            Email = "admin@tenant-alpha.local",
            Name = "Alpha Admin",
            Role = UserRole.TenantAdmin,
            PasswordHash = PasswordHasher.HashPassword("AdminPassword123!"),
            CreatedAt = DateTime.UtcNow
        };

        var secEngUser = new User
        {
            Id = Guid.Parse("88888888-8888-8888-8888-888888888888"),
            TenantId = tenantA.Id,
            Email = "seceng@tenant-alpha.local",
            Name = "Alpha SecEng",
            Role = UserRole.SecurityEngineer,
            PasswordHash = PasswordHasher.HashPassword("SecEngPassword123!"),
            CreatedAt = DateTime.UtcNow
        };

        var devUser = new User
        {
            Id = Guid.Parse("77777777-7777-7777-7777-777777777777"),
            TenantId = tenantA.Id,
            Email = "dev@tenant-alpha.local",
            Name = "Alpha Dev",
            Role = UserRole.Developer,
            PasswordHash = PasswordHasher.HashPassword("DevPassword123!"),
            CreatedAt = DateTime.UtcNow
        };

        var auditorUser = new User
        {
            Id = Guid.Parse("66666666-6666-6666-6666-666666666666"),
            TenantId = tenantA.Id,
            Email = "auditor@tenant-alpha.local",
            Name = "Alpha Auditor",
            Role = UserRole.Auditor,
            PasswordHash = PasswordHasher.HashPassword("AuditorPassword123!"),
            CreatedAt = DateTime.UtcNow
        };

        // Also add an admin user for Tenant B
        var tenantBAdmin = new User
        {
            Id = Guid.Parse("55555555-5555-5555-5555-555555555555"),
            TenantId = tenantB.Id,
            Email = "admin@tenant-beta.local",
            Name = "Beta Admin",
            Role = UserRole.TenantAdmin,
            PasswordHash = PasswordHasher.HashPassword("AdminPassword123!"),
            CreatedAt = DateTime.UtcNow
        };

        // Set tenant session to tenant A and save tenant A users
        await context.Database.ExecuteSqlInterpolatedAsync($"SELECT set_config('app.current_tenant_id', {tenantA.Id.ToString()}, false);");
        context.Users.AddRange(adminUser, secEngUser, devUser, auditorUser);
        await context.SaveChangesAsync();

        // Set tenant session to tenant B and save tenant B user
        await context.Database.ExecuteSqlInterpolatedAsync($"SELECT set_config('app.current_tenant_id', {tenantB.Id.ToString()}, false);");
        context.Users.Add(tenantBAdmin);
        await context.SaveChangesAsync();

    }

    private static async Task SeedVulnerabilitiesAsync(AppDbContext context)
    {
        if (!await context.Vulnerabilities.AnyAsync())
        {
            context.Vulnerabilities.AddRange(
                new Vulnerability
                {
                    Id = Guid.NewGuid(),
                    CveId = "CVE-2021-23337",
                    Summary = "Command Injection in lodash",
                    Description = "lodash versions prior to 4.17.21 are vulnerable to Command Injection via template function.",
                    Severity = FindingSeverity.High,
                    CvssScore = 7.2,
                    CweId = "CWE-78",
                    AffectedPurlPattern = "pkg:npm/lodash",
                    AffectedVersionRange = "<4.17.21",
                    FixedVersion = "4.17.21",
                    IsKev = false,
                    EpssScore = 0.85,
                    CreatedAt = DateTime.UtcNow
                },
                new Vulnerability
                {
                    Id = Guid.NewGuid(),
                    CveId = "CVE-2018-18074",
                    Summary = "Sensitive Header Leak in requests",
                    Description = "The Requests package before 2.20.0 or specified versions can leak sensitive headers upon HTTP redirect.",
                    Severity = FindingSeverity.Medium,
                    CvssScore = 5.3,
                    CweId = "CWE-200",
                    AffectedPurlPattern = "pkg:pypi/requests",
                    AffectedVersionRange = "<2.20.0",
                    FixedVersion = "2.20.0",
                    IsKev = false,
                    EpssScore = 0.25,
                    CreatedAt = DateTime.UtcNow
                }
            );
            await context.SaveChangesAsync();
        }
    }
}
