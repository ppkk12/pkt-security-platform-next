using Microsoft.EntityFrameworkCore;
using PktSecurity.Application.Common.Interfaces;
using PktSecurity.Infrastructure.Data;

namespace PktSecurity.Api.Endpoints;

public static class HealthEndpoints
{
    public static void MapHealthEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/health").WithTags("Health").AllowAnonymous();

        group.MapGet("/live", () => Results.Ok(new
        {
            status = "Healthy",
            timestamp = DateTime.UtcNow
        }));

        group.MapGet("/ready", async (
            AppDbContext db,
            IJobQueueProvider jobQueue,
            CancellationToken cancellationToken) =>
        {
            try
            {
                var canConnect = await db.Database.CanConnectAsync(cancellationToken);
                if (!canConnect)
                {
                    return Results.Problem(
                        statusCode: StatusCodes.Status503ServiceUnavailable,
                        title: "Service Unavailable",
                        detail: "Database connection failed");
                }

                // Verify job queue table connectivity & queue state
                var queuedJobs = await db.ScanJobs.CountAsync(j => j.Status == Domain.Enums.ScanJobStatus.Queued, cancellationToken);

                return Results.Ok(new
                {
                    status = "Ready",
                    database = "Connected",
                    jobQueue = "Operational",
                    queuedJobs,
                    timestamp = DateTime.UtcNow
                });
            }
            catch (Exception ex)
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status503ServiceUnavailable,
                    title: "Service Unavailable",
                    detail: $"Readiness check failed: {ex.Message}");
            }
        });
    }
}
