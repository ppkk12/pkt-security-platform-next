using Microsoft.AspNetCore.Mvc;
using PktSecurity.Application.Common.Interfaces;
using PktSecurity.Application.DTOs;
using PktSecurity.Domain.Enums;

namespace PktSecurity.Api.Endpoints;

public static class SbomEndpoints
{
    public static void MapSbomEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/projects/{id:guid}").WithTags("SBOM & VEX").RequireAuthorization();

        // 1. Upload / Import CycloneDX SBOM
        group.MapPost("/sbom/upload", async (
            Guid id,
            HttpRequest httpRequest,
            ISbomService sbomService,
            ITenantContext tenantContext,
            CancellationToken cancellationToken) =>
        {
            var tenantId = tenantContext.CurrentTenantId
                ?? throw new InvalidOperationException("Tenant context required");

            Stream stream;
            if (httpRequest.HasFormContentType && httpRequest.Form.Files.Count > 0)
            {
                var file = httpRequest.Form.Files[0];
                stream = file.OpenReadStream();
            }
            else
            {
                stream = httpRequest.Body;
            }

            using (stream)
            {
                var result = await sbomService.ImportCycloneDxAsync(tenantId, id, stream, cancellationToken);
                return Results.Ok(result);
            }
        }).DisableAntiforgery();

        // 2. Fast SBOM Re-scan
        group.MapPost("/sbom/rescan", async (
            Guid id,
            ISbomService sbomService,
            ITenantContext tenantContext,
            CancellationToken cancellationToken) =>
        {
            var tenantId = tenantContext.CurrentTenantId
                ?? throw new InvalidOperationException("Tenant context required");

            var result = await sbomService.RescanSbomAsync(tenantId, id, cancellationToken);
            return Results.Ok(result);
        });

        // 3. List Dependencies
        group.MapGet("/sbom/dependencies", async (
            Guid id,
            ISbomService sbomService,
            ITenantContext tenantContext,
            CancellationToken cancellationToken) =>
        {
            var tenantId = tenantContext.CurrentTenantId
                ?? throw new InvalidOperationException("Tenant context required");

            var dependencies = await sbomService.GetProjectDependenciesAsync(tenantId, id, cancellationToken);
            return Results.Ok(dependencies);
        });

        // 4. Register OpenVEX Statement
        group.MapPost("/vex", async (
            Guid id,
            [FromBody] RegisterVexStatementRequest request,
            ISbomService sbomService,
            ITenantContext tenantContext,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            if (httpContext.User.IsInRole(nameof(UserRole.Auditor)))
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status403Forbidden,
                    title: "Forbidden",
                    detail: "Auditors cannot register OpenVEX statements");
            }

            var tenantId = tenantContext.CurrentTenantId
                ?? throw new InvalidOperationException("Tenant context required");

            var result = await sbomService.RegisterVexStatementAsync(tenantId, id, request, cancellationToken);
            return Results.Ok(result);
        });

        // 5. Get OpenVEX Statements
        group.MapGet("/vex", async (
            Guid id,
            ISbomService sbomService,
            ITenantContext tenantContext,
            CancellationToken cancellationToken) =>
        {
            var tenantId = tenantContext.CurrentTenantId
                ?? throw new InvalidOperationException("Tenant context required");

            var statements = await sbomService.GetVexStatementsAsync(tenantId, id, cancellationToken);
            return Results.Ok(statements);
        });
    }
}
