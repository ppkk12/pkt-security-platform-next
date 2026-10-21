using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using PktSecurity.Api.Authentication;
using PktSecurity.Api.Endpoints;
using PktSecurity.Api.Middleware;
using PktSecurity.Application.Common.Interfaces;
using PktSecurity.Application.Common.Models;
using PktSecurity.Infrastructure;
using PktSecurity.Infrastructure.Data;
using PktSecurity.Infrastructure.Jobs;
using PktSecurity.Infrastructure.Security;
using PktSecurity.Infrastructure.Services;

var builder = WebApplication.CreateBuilder(args);

var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "PktSecurity";
var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "PktSecurityUsers";
var jwtKey = builder.Configuration["Jwt:Key"];

if (string.IsNullOrWhiteSpace(jwtKey) || (builder.Environment.IsProduction() && jwtKey == "PktSecuritySuperSecretKeyThatIsAtLeast32BytesLong!"))
{
    if (builder.Environment.IsProduction())
    {
        throw new InvalidOperationException("Fatal Security Error: 'Jwt:Key' must be explicitly configured with a secure non-default key in production environment.");
    }
    jwtKey = "PktSecuritySuperSecretKeyThatIsAtLeast32BytesLong!";
}

builder.Services.AddInfrastructure(builder.Configuration);

// CORS for Frontend (PktSecurity.Web)
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

// Authentication (Smart routing for JWT & ApiKey)
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = "SmartScheme";
    options.DefaultChallengeScheme = "SmartScheme";
})
.AddPolicyScheme("SmartScheme", "JWT or ApiKey", options =>
{
    options.ForwardDefaultSelector = context =>
    {
        if (context.Request.Headers.ContainsKey("X-API-Key"))
        {
            return ApiKeyAuthenticationHandler.SchemeName;
        }

        var auth = context.Request.Headers.Authorization.ToString();
        if (auth.StartsWith("Bearer pkt_live_", StringComparison.OrdinalIgnoreCase))
        {
            return ApiKeyAuthenticationHandler.SchemeName;
        }

        return JwtBearerDefaults.AuthenticationScheme;
    };
})
.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = jwtIssuer,
        ValidateAudience = true,
        ValidAudience = jwtAudience,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromMinutes(1)
    };
})
.AddScheme<ApiKeyAuthenticationOptions, ApiKeyAuthenticationHandler>(ApiKeyAuthenticationHandler.SchemeName, null);

builder.Services.AddAuthorization();
builder.Services.AddMemoryCache();

// OpenTelemetry Instrumentation
builder.Services.AddOpenTelemetry()
    .ConfigureResource(resource => resource.AddService("PktSecurity.Api"))
    .WithTracing(tracing =>
    {
        tracing
            .AddAspNetCoreInstrumentation()
            .AddHttpClientInstrumentation()
            .AddSource("PktSecurity.*");
    })
    .WithMetrics(metrics =>
    {
        metrics
            .AddAspNetCoreInstrumentation()
            .AddHttpClientInstrumentation()
            .AddMeter("PktSecurity.*");
    });

// OpenAPI
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "PktSecurity Platform Next API", Version = "v1" });
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme or API Key",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

var app = builder.Build();

// Auto-migrate / initialize RLS in development / startup
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    try
    {
        await DatabaseInitializer.InitializeDatabaseAsync(db);
    }
    catch (Exception ex)
    {
        app.Logger.LogWarning(ex, "Database auto-initialization deferred or already initialized.");
    }
}

app.UseMiddleware<ProblemDetailsMiddleware>();
app.UseCors();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();
app.UseMiddleware<TenantResolutionMiddleware>();
app.UseAuthorization();

// Map Endpoint Groups
app.MapHealthEndpoints();
app.MapAuthEndpoints();
app.MapDashboardEndpoints();
app.MapProjectEndpoints();
app.MapScanEndpoints();
app.MapFindingEndpoints();
app.MapExportEndpoints();
app.MapSbomEndpoints();
app.MapRemediationEndpoints();
app.MapAuditEndpoints();

app.Run();

// Make Program public for WebApplicationFactory in tests
public partial class Program { }
