using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PktSecurity.Application.Common.Interfaces;
using PktSecurity.Application.DTOs;
using PktSecurity.Domain.Entities;
using PktSecurity.Domain.Enums;
using PktSecurity.Infrastructure.Data;

namespace PktSecurity.Api.Endpoints;

public record UpdateFindingStatusRequest(FindingStatus Status, string? Reason);

public static class FindingEndpoints
{
    public static void MapFindingEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/findings").WithTags("Findings").RequireAuthorization();

        group.MapGet("/", async (
            [AsParameters] FindingSearchQuery query,
            IFindingSearchService searchService,
            CancellationToken cancellationToken) =>
        {
            var result = await searchService.SearchFindingsAsync(query, cancellationToken);
            return Results.Ok(result);
        });

        group.MapGet("/{id:guid}", async (
            Guid id,
            IFindingSearchService searchService,
            CancellationToken cancellationToken) =>
        {
            var finding = await searchService.GetFindingDetailAsync(id, cancellationToken);
            if (finding == null)
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status404NotFound,
                    title: "Not Found",
                    detail: $"Finding {id} not found");
            }

            return Results.Ok(finding);
        });

        group.MapPatch("/{id:guid}/status", async (
            Guid id,
            [FromBody] UpdateFindingStatusRequest request,
            AppDbContext db,
            ITenantContext tenantContext,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            if (httpContext.User.IsInRole(nameof(UserRole.Auditor)))
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status403Forbidden,
                    title: "Forbidden",
                    detail: "Auditors cannot modify finding statuses");
            }

            if (request.Status == FindingStatus.RiskAccepted)
            {
                var isAllowed = httpContext.User.IsInRole(nameof(UserRole.SecurityEngineer)) ||
                                httpContext.User.IsInRole(nameof(UserRole.TenantAdmin)) ||
                                httpContext.User.IsInRole(nameof(UserRole.SystemAdmin));

                if (!isAllowed)
                {
                    return Results.Problem(
                        statusCode: StatusCodes.Status403Forbidden,
                        title: "Forbidden",
                        detail: "Only SecurityEngineer or TenantAdmin can approve RiskAccepted status");
                }
            }

            var finding = await db.Findings
                .FirstOrDefaultAsync(f => f.Id == id, cancellationToken);

            if (finding == null)
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status404NotFound,
                    title: "Not Found",
                    detail: $"Finding {id} not found");
            }

            var fromStatus = finding.Status;
            finding.Status = request.Status;
            finding.UpdatedAt = DateTime.UtcNow;

            var userIdClaim = httpContext.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier);
            Guid? userId = userIdClaim != null && Guid.TryParse(userIdClaim.Value, out var parsedUid) ? parsedUid : null;

            var history = new FindingStatusHistory
            {
                Id = Guid.NewGuid(),
                TenantId = finding.TenantId,
                FindingId = finding.Id,
                FromStatus = fromStatus,
                ToStatus = request.Status,
                Reason = request.Reason,
                ChangedByUserId = userId,
                ApprovedByUserId = request.Status == FindingStatus.RiskAccepted ? userId : null,
                CreatedAt = DateTime.UtcNow
            };

            db.FindingStatusHistories.Add(history);
            await db.SaveChangesAsync(cancellationToken);

            return Results.Ok(new
            {
                findingId = finding.Id,
                fromStatus,
                toStatus = finding.Status,
                reason = request.Reason,
                updatedAt = finding.UpdatedAt
            });
        });
    }
}
