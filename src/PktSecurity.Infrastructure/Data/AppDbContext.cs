using Microsoft.EntityFrameworkCore;
using PktSecurity.Application.Common.Interfaces;
using PktSecurity.Domain.Common;
using PktSecurity.Domain.Entities;

namespace PktSecurity.Infrastructure.Data;

public class AppDbContext : DbContext
{
    private readonly ITenantContext? _tenantContext;

    public AppDbContext(DbContextOptions<AppDbContext> options, ITenantContext? tenantContext = null)
        : base(options)
    {
        _tenantContext = tenantContext;
    }

    public DbSet<Organization> Organizations => Set<Organization>();
    public DbSet<Tenant> Tenants => Set<Tenant>();
    public DbSet<User> Users => Set<User>();
    public DbSet<ApiKey> ApiKeys => Set<ApiKey>();
    public DbSet<Project> Projects => Set<Project>();
    public DbSet<Repository> Repositories => Set<Repository>();
    public DbSet<Scan> Scans => Set<Scan>();
    public DbSet<ScanJob> ScanJobs => Set<ScanJob>();
    public DbSet<Finding> Findings => Set<Finding>();
    public DbSet<FindingEvidence> FindingEvidences => Set<FindingEvidence>();
    public DbSet<FindingStatusHistory> FindingStatusHistories => Set<FindingStatusHistory>();
    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();
    public DbSet<RiskAssessment> RiskAssessments => Set<RiskAssessment>();
    public DbSet<Package> Packages => Set<Package>();
    public DbSet<Vulnerability> Vulnerabilities => Set<Vulnerability>();
    public DbSet<SbomDocument> SbomDocuments => Set<SbomDocument>();
    public DbSet<ProjectDependency> ProjectDependencies => Set<ProjectDependency>();
    public DbSet<VexStatement> VexStatements => Set<VexStatement>();
    public DbSet<Remediation> Remediations => Set<Remediation>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Global query filter for ITenantScoped entities
        foreach (var entityType in modelBuilder.Model.GetEntityTypes())
        {
            if (typeof(ITenantScoped).IsAssignableFrom(entityType.ClrType))
            {
                var method = typeof(AppDbContext)
                    .GetMethod(nameof(ConfigureTenantFilter), System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)?
                    .MakeGenericMethod(entityType.ClrType);

                method?.Invoke(this, new object[] { modelBuilder });
            }
        }

        // Project configurations
        modelBuilder.Entity<Project>(b =>
        {
            b.ToTable("projects");
            b.HasKey(p => p.Id);
            b.HasIndex(p => new { p.TenantId, p.Name });
        });

        // Repository configurations
        modelBuilder.Entity<Repository>(b =>
        {
            b.ToTable("repositories");
            b.HasKey(r => r.Id);
            b.HasOne(r => r.Project)
                .WithMany(p => p.Repositories)
                .HasForeignKey(r => r.ProjectId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // Scan configurations
        modelBuilder.Entity<Scan>(b =>
        {
            b.ToTable("scans");
            b.HasKey(s => s.Id);
            b.HasIndex(s => new { s.TenantId, s.ProjectId, s.CreatedAt });
            b.HasIndex(s => new { s.TenantId, s.IdempotencyKey }).IsUnique(false);
            b.HasOne(s => s.Project)
                .WithMany(p => p.Scans)
                .HasForeignKey(s => s.ProjectId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // ScanJob configurations
        modelBuilder.Entity<ScanJob>(b =>
        {
            b.ToTable("scan_jobs");
            b.HasKey(j => j.Id);
            b.HasIndex(j => new { j.Status, j.Priority, j.CreatedAt });
            b.HasIndex(j => new { j.LeasedUntil, j.Status });
            b.HasOne(j => j.Scan)
                .WithMany(s => s.Jobs)
                .HasForeignKey(j => j.ScanId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // Finding configurations
        modelBuilder.Entity<Finding>(b =>
        {
            b.ToTable("findings");
            b.HasKey(f => f.Id);

            b.HasIndex(f => new { f.TenantId, f.Status, f.RiskScore, f.Id })
                .HasDatabaseName("ix_findings_tenant_status_risk");

            b.HasIndex(f => new { f.TenantId, f.RiskScore, f.Id })
                .HasDatabaseName("ix_findings_tenant_risk_id");

            b.HasIndex(f => new { f.TenantId, f.Severity, f.RiskScore, f.Id })
                .HasDatabaseName("ix_findings_tenant_sev_risk_id");

            b.HasIndex(f => new { f.TenantId, f.IsKev, f.RiskScore, f.Id })
                .HasDatabaseName("ix_findings_tenant_kev_risk_id");

            b.HasIndex(f => new { f.TenantId, f.ProjectId, f.Severity, f.RiskScore, f.Id })
                .HasDatabaseName("ix_findings_tenant_project_sev");

            b.HasIndex(f => new { f.TenantId, f.ProjectId, f.PrimaryFingerprint })
                .IsUnique()
                .HasDatabaseName("ux_findings_tenant_project_fp1");

            b.HasIndex(f => new { f.TenantId, f.ProjectId, f.SecondaryFingerprint })
                .HasDatabaseName("ix_findings_tenant_project_fp2");

            b.HasIndex(f => new { f.TenantId, f.CorrelationGroupId });

            b.HasOne(f => f.Project)
                .WithMany(p => p.Findings)
                .HasForeignKey(f => f.ProjectId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // FindingEvidence configurations
        modelBuilder.Entity<FindingEvidence>(b =>
        {
            b.ToTable("finding_evidences");
            b.HasKey(e => e.Id);
            b.HasOne(e => e.Finding)
                .WithMany(f => f.Evidences)
                .HasForeignKey(e => e.FindingId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // FindingStatusHistory configurations
        modelBuilder.Entity<FindingStatusHistory>(b =>
        {
            b.ToTable("finding_status_history");
            b.HasKey(h => h.Id);
            b.HasOne(h => h.Finding)
                .WithMany(f => f.StatusHistory)
                .HasForeignKey(h => h.FindingId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // User & ApiKey configurations
        modelBuilder.Entity<User>(b =>
        {
            b.ToTable("users");
            b.HasKey(u => u.Id);
            b.HasIndex(u => new { u.TenantId, u.Email }).IsUnique();
        });

        modelBuilder.Entity<ApiKey>(b =>
        {
            b.ToTable("api_keys");
            b.HasKey(k => k.Id);
            b.HasIndex(k => new { k.TenantId, k.KeyHash }).IsUnique();
        });

        modelBuilder.Entity<AuditEvent>(b =>
        {
            b.ToTable("audit_events");
            b.HasKey(a => a.Id);
            b.HasIndex(a => new { a.TenantId, a.CreatedAt });
        });

        modelBuilder.Entity<Organization>(b =>
        {
            b.ToTable("organizations");
            b.HasKey(o => o.Id);
        });

        modelBuilder.Entity<Tenant>(b =>
        {
            b.ToTable("tenants");
            b.HasKey(t => t.Id);
            b.HasOne(t => t.Organization)
                .WithMany(o => o.Tenants)
                .HasForeignKey(t => t.OrganizationId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<RiskAssessment>(b =>
        {
            b.ToTable("risk_assessments");
            b.HasKey(r => r.Id);
            b.HasIndex(r => new { r.TenantId, r.FindingId });
            b.HasOne(r => r.Finding)
                .WithMany(f => f.RiskAssessments)
                .HasForeignKey(r => r.FindingId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<Package>(b =>
        {
            b.ToTable("packages");
            b.HasKey(p => p.Id);
            b.HasIndex(p => p.Purl).IsUnique();
        });

        modelBuilder.Entity<Vulnerability>(b =>
        {
            b.ToTable("vulnerabilities");
            b.HasKey(v => v.Id);
            b.HasIndex(v => v.CveId).IsUnique();
        });

        modelBuilder.Entity<SbomDocument>(b =>
        {
            b.ToTable("sbom_documents");
            b.HasKey(s => s.Id);
            b.HasIndex(s => new { s.TenantId, s.ProjectId, s.CreatedAt });
            b.HasOne(s => s.Project)
                .WithMany(p => p.SbomDocuments)
                .HasForeignKey(s => s.ProjectId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<ProjectDependency>(b =>
        {
            b.ToTable("project_dependencies");
            b.HasKey(d => d.Id);
            b.HasIndex(d => new { d.TenantId, d.ProjectId, d.PackagePurl });
            b.HasOne(d => d.Project)
                .WithMany(p => p.Dependencies)
                .HasForeignKey(d => d.ProjectId)
                .OnDelete(DeleteBehavior.Cascade);
            b.HasOne(d => d.SbomDocument)
                .WithMany(s => s.Dependencies)
                .HasForeignKey(d => d.SbomDocumentId)
                .OnDelete(DeleteBehavior.Cascade);
            b.HasOne(d => d.Package)
                .WithMany(p => p.Dependencies)
                .HasForeignKey(d => d.PackageId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<VexStatement>(b =>
        {
            b.ToTable("vex_statements");
            b.HasKey(v => v.Id);
            b.HasIndex(v => new { v.TenantId, v.ProjectId, v.VulnerabilityId });
            b.HasOne(v => v.Project)
                .WithMany(p => p.VexStatements)
                .HasForeignKey(v => v.ProjectId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<Remediation>(b =>
        {
            b.ToTable("remediations");
            b.HasKey(r => r.Id);
            b.HasIndex(r => new { r.TenantId, r.FindingId });
            b.HasOne(r => r.Finding)
                .WithMany(f => f.Remediations)
                .HasForeignKey(r => r.FindingId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // Apply snake_case naming convention across all entities and properties
        foreach (var entity in modelBuilder.Model.GetEntityTypes())
        {
            var tableName = entity.GetTableName();
            if (!string.IsNullOrEmpty(tableName))
            {
                entity.SetTableName(ToSnakeCase(tableName));
            }

            foreach (var property in entity.GetProperties())
            {
                property.SetColumnName(ToSnakeCase(property.Name));
            }

            foreach (var key in entity.GetKeys())
            {
                var keyName = key.GetName();
                if (!string.IsNullOrEmpty(keyName))
                    key.SetName(ToSnakeCase(keyName));
            }

            foreach (var fk in entity.GetForeignKeys())
            {
                var constraintName = fk.GetConstraintName();
                if (!string.IsNullOrEmpty(constraintName))
                    fk.SetConstraintName(ToSnakeCase(constraintName));
            }

            foreach (var index in entity.GetIndexes())
            {
                var indexName = index.GetDatabaseName();
                if (!string.IsNullOrEmpty(indexName))
                    index.SetDatabaseName(ToSnakeCase(indexName));
            }
        }
    }

    private static string ToSnakeCase(string input)
    {
        if (string.IsNullOrEmpty(input)) return input;
        return System.Text.RegularExpressions.Regex.Replace(
            input,
            @"([a-z0-9])([A-Z])",
            "$1_$2").ToLowerInvariant();
    }

    private void ConfigureTenantFilter<T>(ModelBuilder modelBuilder) where T : class, ITenantScoped
    {
        modelBuilder.Entity<T>().HasQueryFilter(e =>
            _tenantContext == null ||
            _tenantContext.CurrentTenantId == null ||
            e.TenantId == _tenantContext.CurrentTenantId);
    }
}
