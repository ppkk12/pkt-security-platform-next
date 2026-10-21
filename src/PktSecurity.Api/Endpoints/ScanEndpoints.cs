using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PktSecurity.Application.Common.Interfaces;
using PktSecurity.Application.DTOs;
using PktSecurity.Domain.Entities;
using PktSecurity.Domain.Enums;
using PktSecurity.Infrastructure.Data;

namespace PktSecurity.Api.Endpoints;

public static class ScanEndpoints
{
    public static void MapScanEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1").WithTags("Scans").RequireAuthorization();

        group.MapPost("/projects/{projectId:guid}/scans", async (
            Guid projectId,
            [FromBody] StartScanRequest? request,
            AppDbContext db,
            ITenantContext tenantContext,
            IAuditService auditService,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            request ??= new StartScanRequest();

            if (!string.IsNullOrWhiteSpace(request.TargetBranch))
            {
                PktSecurity.Infrastructure.Security.ArgumentValidator.ValidateGitBranch(request.TargetBranch);
            }
            if (httpContext.User.IsInRole(nameof(UserRole.Auditor)))
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status403Forbidden,
                    title: "Forbidden",
                    detail: "Auditors cannot trigger scans");
            }

            var tenantId = tenantContext.CurrentTenantId;
            if (!tenantId.HasValue)
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status401Unauthorized,
                    title: "Unauthorized",
                    detail: "Tenant context missing");
            }

            var project = await db.Projects
                .Include(p => p.Repositories)
                .FirstOrDefaultAsync(p => p.Id == projectId, cancellationToken);

            if (project == null)
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status404NotFound,
                    title: "Not Found",
                    detail: $"Project {projectId} not found");
            }

            // Check Idempotency-Key header
            string? idempotencyKey = null;
            if (httpContext.Request.Headers.TryGetValue("Idempotency-Key", out var ikeyHeader))
            {
                idempotencyKey = ikeyHeader.ToString();
                if (!string.IsNullOrWhiteSpace(idempotencyKey))
                {
                    var existingScan = await db.Scans
                        .Include(s => s.Jobs)
                        .FirstOrDefaultAsync(s => s.ProjectId == projectId && s.IdempotencyKey == idempotencyKey, cancellationToken);

                    if (existingScan != null)
                    {
                        return Results.Ok(MapToScanDto(existingScan));
                    }
                }
            }

            // If target directory is specified in request or repo, ensure repo exists
            if (!string.IsNullOrWhiteSpace(request.TargetDirectory))
            {
                var repo = project.Repositories.FirstOrDefault();
                if (repo == null)
                {
                    project.Repositories.Add(new Repository
                    {
                        Id = Guid.NewGuid(),
                        TenantId = tenantId.Value,
                        ProjectId = project.Id,
                        RepoUrl = request.TargetDirectory,
                        DefaultBranch = request.TargetBranch ?? "main",
                        CreatedAt = DateTime.UtcNow
                    });
                }
                else
                {
                    repo.RepoUrl = request.TargetDirectory;
                }
            }

            var scan = new Scan
            {
                Id = Guid.NewGuid(),
                TenantId = tenantId.Value,
                ProjectId = projectId,
                Status = ScanStatus.Queued,
                TargetBranch = request.TargetBranch ?? "main",
                CommitHash = request.CommitHash,
                IdempotencyKey = idempotencyKey,
                CreatedAt = DateTime.UtcNow
            };

            var scannerNames = request.Scanners != null && request.Scanners.Count > 0
                ? request.Scanners
                : new[] { "native" };

            foreach (var sName in scannerNames)
            {
                scan.Jobs.Add(new ScanJob
                {
                    Id = Guid.NewGuid(),
                    TenantId = tenantId.Value,
                    ScanId = scan.Id,
                    ScannerName = sName,
                    Status = ScanJobStatus.Queued,
                    Priority = 100,
                    AttemptCount = 0,
                    MaxAttempts = 3,
                    CreatedAt = DateTime.UtcNow
                });
            }

            db.Scans.Add(scan);
            await db.SaveChangesAsync(cancellationToken);

            var userIdStr = httpContext.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
                ?? httpContext.User.FindFirst("sub")?.Value;
            var userId = Guid.TryParse(userIdStr, out var parsedUid) ? parsedUid : (Guid?)null;

            await auditService.RecordEventAsync(
                tenantId.Value,
                "scan.queued",
                userId,
                "Queued Scan",
                new { ScanId = scan.Id, ProjectId = projectId },
                cancellationToken);

            return Results.Accepted($"/api/v1/scans/{scan.Id}", MapToScanDto(scan));
        });

        group.MapGet("/scans/{id:guid}", async (
            Guid id,
            AppDbContext db,
            CancellationToken cancellationToken) =>
        {
            var scan = await db.Scans
                .AsNoTracking()
                .Include(s => s.Jobs)
                .FirstOrDefaultAsync(s => s.Id == id, cancellationToken);

            if (scan == null)
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status404NotFound,
                    title: "Not Found",
                    detail: $"Scan {id} not found");
            }

            return Results.Ok(MapToScanDto(scan));
        });

        group.MapGet("/scans/{id:guid}/events", async (
            Guid id,
            AppDbContext db,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var response = httpContext.Response;
            response.Headers.Append("Content-Type", "text/event-stream");
            response.Headers.Append("Cache-Control", "no-cache");
            response.Headers.Append("Connection", "keep-alive");

            var pollInterval = TimeSpan.FromMilliseconds(500);

            while (!cancellationToken.IsCancellationRequested)
            {
                var scan = await db.Scans
                    .AsNoTracking()
                    .Include(s => s.Jobs)
                    .FirstOrDefaultAsync(s => s.Id == id, cancellationToken);

                if (scan == null)
                {
                    var notFoundPayload = JsonSerializer.Serialize(new { error = "Scan not found", scanId = id });
                    await response.WriteAsync($"event: error\ndata: {notFoundPayload}\n\n", cancellationToken);
                    await response.Body.FlushAsync(cancellationToken);
                    break;
                }

                var scanDto = MapToScanDto(scan);
                var payload = JsonSerializer.Serialize(scanDto);
                await response.WriteAsync($"event: scan.progress\ndata: {payload}\n\n", cancellationToken);
                await response.Body.FlushAsync(cancellationToken);

                if (scan.Status == ScanStatus.Completed || scan.Status == ScanStatus.Failed || scan.Status == ScanStatus.Cancelled)
                {
                    var eventName = scan.Status == ScanStatus.Completed ? "scan.completed" : "scan.finished";
                    await response.WriteAsync($"event: {eventName}\ndata: {payload}\n\n", cancellationToken);
                    await response.Body.FlushAsync(cancellationToken);
                    break;
                }

                try
                {
                    await Task.Delay(pollInterval, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        });

        group.MapPost("/scans/{id:guid}/cancel", async (
            Guid id,
            AppDbContext db,
            IJobQueueProvider queueProvider,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            if (httpContext.User.IsInRole(nameof(UserRole.Auditor)))
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status403Forbidden,
                    title: "Forbidden",
                    detail: "Auditors cannot cancel scans");
            }

            var scan = await db.Scans
                .Include(s => s.Jobs)
                .FirstOrDefaultAsync(s => s.Id == id, cancellationToken);

            if (scan == null)
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status404NotFound,
                    title: "Not Found",
                    detail: $"Scan {id} not found");
            }

            scan.Status = ScanStatus.Cancelled;

            foreach (var job in scan.Jobs)
            {
                if (job.Status is ScanJobStatus.Queued or ScanJobStatus.Running)
                {
                    job.CancelRequested = true;
                    job.Status = ScanJobStatus.Cancelled;
                    await queueProvider.CancelJobAsync(job.Id, cancellationToken);
                }
            }

            await db.SaveChangesAsync(cancellationToken);
            return Results.Ok(new { message = $"Scan {id} cancellation initiated" });
        });
    }

    private static ScanDto MapToScanDto(Scan scan)
    {
        return new ScanDto
        {
            Id = scan.Id,
            ProjectId = scan.ProjectId,
            Status = scan.Status,
            TargetBranch = scan.TargetBranch,
            CommitHash = scan.CommitHash,
            IdempotencyKey = scan.IdempotencyKey,
            CreatedAt = scan.CreatedAt,
            CompletedAt = scan.CompletedAt,
            ErrorMessage = scan.ErrorMessage,
            Jobs = scan.Jobs.Select(j => new ScanJobDto
            {
                Id = j.Id,
                ScanId = j.ScanId,
                ScannerName = j.ScannerName,
                Status = j.Status,
                AttemptCount = j.AttemptCount,
                ExecutionDurationMs = j.ExecutionDurationMs,
                ErrorMessage = j.ErrorMessage,
                CreatedAt = j.CreatedAt
            }).ToList()
        };
    }
}
