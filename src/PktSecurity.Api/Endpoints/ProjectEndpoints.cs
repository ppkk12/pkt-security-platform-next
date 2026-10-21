using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PktSecurity.Application.Common.Interfaces;
using PktSecurity.Application.DTOs;
using PktSecurity.Domain.Entities;
using PktSecurity.Domain.Enums;
using PktSecurity.Infrastructure.Data;

namespace PktSecurity.Api.Endpoints;

public static class ProjectEndpoints
{
    public static void MapProjectEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/projects").WithTags("Projects").RequireAuthorization();

        group.MapPost("/", async (
            [FromBody] CreateProjectRequest request,
            AppDbContext db,
            ITenantContext tenantContext,
            IAuditService auditService,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            if (httpContext.User.IsInRole(nameof(UserRole.Auditor)))
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status403Forbidden,
                    title: "Forbidden",
                    detail: "Auditors cannot create projects");
            }

            var tenantId = tenantContext.CurrentTenantId;
            if (!tenantId.HasValue)
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status401Unauthorized,
                    title: "Unauthorized",
                    detail: "Tenant context missing");
            }

            var project = new Project
            {
                Id = Guid.NewGuid(),
                TenantId = tenantId.Value,
                Name = request.Name,
                Description = request.Description,
                BusinessCriticality = request.BusinessCriticality,
                IsInternetFacing = request.IsInternetFacing,
                DataSensitivity = request.DataSensitivity,
                CreatedAt = DateTime.UtcNow
            };

            if (!string.IsNullOrWhiteSpace(request.RepositoryUrl))
            {
                project.Repositories.Add(new Repository
                {
                    Id = Guid.NewGuid(),
                    TenantId = tenantId.Value,
                    ProjectId = project.Id,
                    RepoUrl = request.RepositoryUrl,
                    DefaultBranch = "main",
                    CreatedAt = DateTime.UtcNow
                });
            }

            db.Projects.Add(project);
            await db.SaveChangesAsync(cancellationToken);

            var userIdStr = httpContext.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
                ?? httpContext.User.FindFirst("sub")?.Value;
            var userId = Guid.TryParse(userIdStr, out var parsedUid) ? parsedUid : (Guid?)null;

            await auditService.RecordEventAsync(
                tenantId.Value,
                "project.created",
                userId,
                "Created Project",
                new { ProjectId = project.Id, Name = project.Name },
                cancellationToken);

            var dto = new ProjectDto
            {
                Id = project.Id,
                TenantId = project.TenantId,
                Name = project.Name,
                Description = project.Description,
                BusinessCriticality = project.BusinessCriticality,
                IsInternetFacing = project.IsInternetFacing,
                DataSensitivity = project.DataSensitivity,
                CreatedAt = project.CreatedAt
            };

            return Results.Created($"/api/v1/projects/{project.Id}", dto);
        });

        group.MapGet("/", async (
            AppDbContext db,
            CancellationToken cancellationToken) =>
        {
            var projects = await db.Projects
                .AsNoTracking()
                .OrderByDescending(p => p.CreatedAt)
                .Select(p => new ProjectDto
                {
                    Id = p.Id,
                    TenantId = p.TenantId,
                    Name = p.Name,
                    Description = p.Description,
                    BusinessCriticality = p.BusinessCriticality,
                    IsInternetFacing = p.IsInternetFacing,
                    DataSensitivity = p.DataSensitivity,
                    CreatedAt = p.CreatedAt
                })
                .ToListAsync(cancellationToken);

            return Results.Ok(projects);
        });

        group.MapGet("/{id:guid}", async (
            Guid id,
            AppDbContext db,
            CancellationToken cancellationToken) =>
        {
            var project = await db.Projects
                .AsNoTracking()
                .FirstOrDefaultAsync(p => p.Id == id, cancellationToken);

            if (project == null)
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status404NotFound,
                    title: "Not Found",
                    detail: $"Project {id} not found");
            }

            return Results.Ok(new ProjectDto
            {
                Id = project.Id,
                TenantId = project.TenantId,
                Name = project.Name,
                Description = project.Description,
                BusinessCriticality = project.BusinessCriticality,
                IsInternetFacing = project.IsInternetFacing,
                DataSensitivity = project.DataSensitivity,
                CreatedAt = project.CreatedAt
            });
        });
    }
}
