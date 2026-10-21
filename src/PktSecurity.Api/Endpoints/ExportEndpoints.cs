using Microsoft.AspNetCore.Mvc;
using PktSecurity.Application.Common.Interfaces;

namespace PktSecurity.Api.Endpoints;

public static class ExportEndpoints
{
    public static void MapExportEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/projects").WithTags("Export").RequireAuthorization();

        group.MapGet("/{projectId:guid}/export", async (
            Guid projectId,
            [FromQuery] string? format,
            IExportService exportService,
            CancellationToken cancellationToken) =>
        {
            var fmt = (format ?? "json").Trim().ToLowerInvariant();
            var bytes = await exportService.ExportProjectFindingsAsync(projectId, fmt, cancellationToken);

            var (contentType, fileName) = fmt switch
            {
                "csv" => ("text/csv", $"findings_project_{projectId}.csv"),
                "sarif" => ("application/sarif+json", $"findings_project_{projectId}.sarif"),
                "cyclonedx" => ("application/vnd.cyclonedx+json", $"sbom_project_{projectId}.cyclonedx.json"),
                "meti" or "meti-audit" or "audit-report" => ("application/json", $"meti_sbom_audit_report_{projectId}.json"),
                _ => ("application/json", $"findings_project_{projectId}.json")
            };

            return Results.File(bytes, contentType, fileName);
        });
    }
}
