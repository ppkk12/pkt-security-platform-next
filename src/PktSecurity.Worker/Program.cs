using Microsoft.EntityFrameworkCore;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using PktSecurity.Application.Common.Interfaces;
using PktSecurity.Application.Common.Models;
using PktSecurity.Infrastructure.Data;
using PktSecurity.Infrastructure.Jobs;
using PktSecurity.Infrastructure.Parsers;
using PktSecurity.Infrastructure.Sandbox;
using PktSecurity.Infrastructure.Scanners;
using PktSecurity.Infrastructure.Services;
using PktSecurity.Worker;

var builder = Host.CreateApplicationBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
if (string.IsNullOrWhiteSpace(connectionString))
{
    if (builder.Environment.IsProduction())
    {
        throw new InvalidOperationException("Fatal Security Error: 'ConnectionStrings:DefaultConnection' must be explicitly configured in production environment.");
    }
    connectionString = "Host=localhost;Port=5432;Database=pktsecurity;Username=postgres;Password=postgres";
}

builder.Services.AddScoped<ITenantContext, TenantContext>();
builder.Services.AddScoped<TenantSecurityInterceptor>();

builder.Services.AddDbContext<AppDbContext>((sp, options) =>
{
    var interceptor = sp.GetRequiredService<TenantSecurityInterceptor>();
    options.UseNpgsql(connectionString)
           .AddInterceptors(interceptor);
});

builder.Services.AddSingleton<IJobQueueProvider>(_ => new PostgresJobQueueProvider(connectionString));

builder.Services.Configure<DockerSandboxOptions>(builder.Configuration.GetSection(DockerSandboxOptions.SectionName));
var sandboxProvider = builder.Configuration["Sandbox:Provider"] ?? 
                      Environment.GetEnvironmentVariable("SANDBOX__PROVIDER") ?? "Process";

if (sandboxProvider.Equals("Docker", StringComparison.OrdinalIgnoreCase))
{
    builder.Services.AddSingleton<ISandboxExecutionProvider, DockerSandboxExecutionProvider>();
}
else
{
    builder.Services.AddSingleton<ISandboxExecutionProvider, ProcessSandboxExecutionProvider>();
}

builder.Services.AddSingleton<SarifStreamingParser>();

builder.Services.AddSingleton<NativeScannerAdapter>();
builder.Services.AddSingleton<IScannerAdapter>(sp => sp.GetRequiredService<NativeScannerAdapter>());
builder.Services.AddSingleton<IScannerAdapter, GitleaksScannerAdapter>();
builder.Services.AddSingleton<IScannerAdapter, TrivyScannerAdapter>();
builder.Services.AddSingleton<IScannerAdapter, SemgrepScannerAdapter>();
builder.Services.AddSingleton<ScannerRegistry>();

builder.Services.AddScoped<ScanExecutionService>();
builder.Services.AddHostedService<ScanWorker>();

// OpenTelemetry Instrumentation
builder.Services.AddOpenTelemetry()
    .ConfigureResource(resource => resource.AddService("PktSecurity.Worker"))
    .WithTracing(tracing => tracing.AddSource("PktSecurity.*"))
    .WithMetrics(metrics => metrics.AddMeter("PktSecurity.*"));

var host = builder.Build();
host.Run();
