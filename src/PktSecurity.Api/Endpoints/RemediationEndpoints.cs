using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using PktSecurity.Application.Common.Interfaces;
using PktSecurity.Application.DTOs;
using PktSecurity.Domain.Enums;

namespace PktSecurity.Api.Endpoints;

public static class RemediationEndpoints
{
    public static void MapRemediationEndpoints(this IEndpointRouteBuilder app)
    {
        var findingsGroup = app.MapGroup("/api/v1/findings/{id:guid}").WithTags("Remediations").RequireAuthorization();

        // 1. Generate Remediation
        findingsGroup.MapPost("/remediate", async (
            Guid id,
            IRemediationService remediationService,
            ITenantContext tenantContext,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            if (httpContext.User.IsInRole(nameof(UserRole.Auditor)))
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status403Forbidden,
                    title: "Forbidden",
                    detail: "Auditors cannot generate remediations");
            }

            var tenantId = tenantContext.CurrentTenantId
                ?? throw new InvalidOperationException("Tenant context required");

            var result = await remediationService.GenerateRemediationAsync(tenantId, id, cancellationToken);
            return Results.Ok(result);
        });

        // 2. Get latest remediation for finding
        findingsGroup.MapGet("/remediation", async (
            Guid id,
            IRemediationService remediationService,
            ITenantContext tenantContext,
            CancellationToken cancellationToken) =>
        {
            var tenantId = tenantContext.CurrentTenantId
                ?? throw new InvalidOperationException("Tenant context required");

            var result = await remediationService.GetRemediationAsync(tenantId, id, cancellationToken);
            if (result == null)
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status404NotFound,
                    title: "Not Found",
                    detail: $"No remediation found for finding {id}");
            }

            return Results.Ok(result);
        });

        var remediationsGroup = app.MapGroup("/api/v1/remediations/{id:guid}").WithTags("Remediations").RequireAuthorization();

        // 3. Verify Remediation in Sandbox
        remediationsGroup.MapPost("/verify", async (
            Guid id,
            IRemediationService remediationService,
            ITenantContext tenantContext,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            if (httpContext.User.IsInRole(nameof(UserRole.Auditor)))
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status403Forbidden,
                    title: "Forbidden",
                    detail: "Auditors cannot verify remediations");
            }

            var tenantId = tenantContext.CurrentTenantId
                ?? throw new InvalidOperationException("Tenant context required");

            var result = await remediationService.VerifyRemediationAsync(tenantId, id, cancellationToken);
            return Results.Ok(result);
        });

        // 4. Human-in-the-Loop Approve Remediation
        remediationsGroup.MapPost("/approve", async (
            Guid id,
            [FromBody] ApproveRemediationRequest? request,
            IRemediationService remediationService,
            ITenantContext tenantContext,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            // Only TenantAdmin, SecurityEngineer, or SystemAdmin can approve
            var isAllowed = httpContext.User.IsInRole(nameof(UserRole.TenantAdmin)) ||
                            httpContext.User.IsInRole(nameof(UserRole.SecurityEngineer)) ||
                            httpContext.User.IsInRole(nameof(UserRole.SystemAdmin));

            if (!isAllowed)
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status403Forbidden,
                    title: "Forbidden",
                    detail: "Only Security Engineers and Admins are authorized to approve remediations");
            }

            var tenantId = tenantContext.CurrentTenantId
                ?? throw new InvalidOperationException("Tenant context required");

            var userIdStr = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier) ??
                            httpContext.User.FindFirstValue("sub");
            var userId = Guid.TryParse(userIdStr, out var parsed) ? parsed : Guid.Empty;

            try
            {
                var result = await remediationService.ApproveRemediationAsync(tenantId, id, userId, cancellationToken);
                return Results.Ok(result);
            }
            catch (KeyNotFoundException ex)
            {
                return Results.Problem(statusCode: StatusCodes.Status404NotFound, title: "Not Found", detail: ex.Message);
            }
            catch (InvalidOperationException ex)
            {
                return Results.Problem(statusCode: StatusCodes.Status400BadRequest, title: "Bad Request", detail: ex.Message);
            }
        });

        // 5. Reject Remediation
        remediationsGroup.MapPost("/reject", async (
            Guid id,
            [FromBody] RejectRemediationRequest? request,
            IRemediationService remediationService,
            ITenantContext tenantContext,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            if (httpContext.User.IsInRole(nameof(UserRole.Auditor)))
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status403Forbidden,
                    title: "Forbidden",
                    detail: "Auditors cannot reject remediations");
            }

            var tenantId = tenantContext.CurrentTenantId
                ?? throw new InvalidOperationException("Tenant context required");

            var userIdStr = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier) ??
                            httpContext.User.FindFirstValue("sub");
            var userId = Guid.TryParse(userIdStr, out var parsed) ? parsed : Guid.Empty;

            var result = await remediationService.RejectRemediationAsync(tenantId, id, userId, request?.Reason, cancellationToken);
            return Results.Ok(result);
        });
    }
}
