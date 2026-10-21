using PktSecurity.Application.Common.Interfaces;
using PktSecurity.Domain.Enums;

namespace PktSecurity.Api.Endpoints;

public static class AuditEndpoints
{
    public static void MapAuditEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/audit-events").WithTags("Audit").RequireAuthorization();

        // 1. Verify Tamper-Evident SHA-256 Hash Chain
        group.MapGet("/verify", async (
            IAuditService auditService,
            ITenantContext tenantContext,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var isAllowed = httpContext.User.IsInRole(nameof(UserRole.TenantAdmin)) ||
                            httpContext.User.IsInRole(nameof(UserRole.SecurityEngineer)) ||
                            httpContext.User.IsInRole(nameof(UserRole.Auditor)) ||
                            httpContext.User.IsInRole(nameof(UserRole.SystemAdmin));

            if (!isAllowed)
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status403Forbidden,
                    title: "Forbidden",
                    detail: "Access to audit logs is restricted to Administrators, Security Engineers, and Auditors.");
            }

            var tenantId = tenantContext.CurrentTenantId
                ?? throw new InvalidOperationException("Tenant context required");

            var result = await auditService.VerifyChainAsync(tenantId, cancellationToken);
            return Results.Ok(result);
        });

        // 2. List Audit Events
        group.MapGet("/", async (
            int? limit,
            IAuditService auditService,
            ITenantContext tenantContext,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var isAllowed = httpContext.User.IsInRole(nameof(UserRole.TenantAdmin)) ||
                            httpContext.User.IsInRole(nameof(UserRole.SecurityEngineer)) ||
                            httpContext.User.IsInRole(nameof(UserRole.Auditor)) ||
                            httpContext.User.IsInRole(nameof(UserRole.SystemAdmin));

            if (!isAllowed)
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status403Forbidden,
                    title: "Forbidden",
                    detail: "Access to audit logs is restricted to Administrators, Security Engineers, and Auditors.");
            }

            var tenantId = tenantContext.CurrentTenantId
                ?? throw new InvalidOperationException("Tenant context required");

            var events = await auditService.GetAuditEventsAsync(tenantId, limit ?? 100, cancellationToken);
            return Results.Ok(events);
        });
    }
}
