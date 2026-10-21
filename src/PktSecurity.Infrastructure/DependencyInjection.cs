using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PktSecurity.Application.Common.Interfaces;
using PktSecurity.Application.Common.Models;
using PktSecurity.Infrastructure.Data;
using PktSecurity.Infrastructure.Jobs;
using PktSecurity.Infrastructure.Parsers;
using PktSecurity.Infrastructure.Sandbox;
using PktSecurity.Infrastructure.Scanners;
using PktSecurity.Infrastructure.Security;
using PktSecurity.Infrastructure.Services;

namespace PktSecurity.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        var env = configuration["ASPNETCORE_ENVIRONMENT"] ?? 
                  Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? 
                  Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT");
        var isProduction = string.Equals(env, "Production", StringComparison.OrdinalIgnoreCase);

        var connectionString = configuration.GetConnectionString("DefaultConnection");
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            if (isProduction)
            {
                throw new InvalidOperationException("Fatal Security Error: 'ConnectionStrings:DefaultConnection' must be explicitly configured in production environment.");
            }
            connectionString = "Host=localhost;Port=5432;Database=pktsecurity;Username=postgres;Password=postgres";
        }

        var jwtIssuer = configuration["Jwt:Issuer"] ?? "PktSecurity";
        var jwtAudience = configuration["Jwt:Audience"] ?? "PktSecurityUsers";
        var jwtKey = configuration["Jwt:Key"];

        if (string.IsNullOrWhiteSpace(jwtKey) || (isProduction && jwtKey == "PktSecuritySuperSecretKeyThatIsAtLeast32BytesLong!"))
        {
            if (isProduction)
            {
                throw new InvalidOperationException("Fatal Security Error: 'Jwt:Key' must be explicitly configured with a secure non-default key in production environment.");
            }
            jwtKey = "PktSecuritySuperSecretKeyThatIsAtLeast32BytesLong!";
        }

        services.AddScoped<ITenantContext, TenantContext>();
        services.AddScoped<TenantSecurityInterceptor>();

        services.AddDbContext<AppDbContext>((sp, options) =>
        {
            var interceptor = sp.GetRequiredService<TenantSecurityInterceptor>();
            options.UseNpgsql(connectionString)
                   .AddInterceptors(interceptor);
        });

        services.AddSingleton<IJobQueueProvider>(_ => new PostgresJobQueueProvider(connectionString));

        services.Configure<DockerSandboxOptions>(configuration.GetSection(DockerSandboxOptions.SectionName));
        var sandboxProvider = configuration["Sandbox:Provider"] ?? 
                              Environment.GetEnvironmentVariable("SANDBOX__PROVIDER") ?? "Process";

        if (sandboxProvider.Equals("Docker", StringComparison.OrdinalIgnoreCase))
        {
            services.AddSingleton<ISandboxExecutionProvider, DockerSandboxExecutionProvider>();
        }
        else
        {
            services.AddSingleton<ISandboxExecutionProvider, ProcessSandboxExecutionProvider>();
        }

        services.AddSingleton<SarifStreamingParser>();
        services.AddSingleton<CycloneDxStreamingParser>();

        services.AddSingleton<NativeScannerAdapter>();
        services.AddSingleton<IScannerAdapter>(sp => sp.GetRequiredService<NativeScannerAdapter>());
        services.AddSingleton<IScannerAdapter, GitleaksScannerAdapter>();
        services.AddSingleton<IScannerAdapter, TrivyScannerAdapter>();
        services.AddSingleton<IScannerAdapter, SemgrepScannerAdapter>();
        services.AddSingleton<ScannerRegistry>();

        services.AddScoped<ScanExecutionService>();
        services.AddScoped<IFindingSearchService, PostgresFindingSearchService>();
        services.AddScoped<IExportService, ExportService>();
        services.AddScoped<ISbomService, SbomService>();
        services.AddScoped<IAuditService, AuditService>();
        services.AddHttpClient<LlmAiRemediationProvider>();
        services.AddSingleton<RuleBasedRemediationProvider>();
        services.AddScoped<IAiRemediationProvider, LlmAiRemediationProvider>();
        services.AddScoped<IRemediationService, RemediationService>();
        services.AddScoped<ApiKeyService>();
        services.AddSingleton(_ => new JwtTokenService(jwtIssuer, jwtAudience, jwtKey));

        return services;
    }
}
