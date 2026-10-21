using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PktSecurity.Application.Common.Interfaces;
using PktSecurity.Application.DTOs;
using PktSecurity.Domain.Enums;
using PktSecurity.Infrastructure.Data;
using PktSecurity.Infrastructure.Security;

namespace PktSecurity.Api.Endpoints;

public static class AuthEndpoints
{
    public static void MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/auth").WithTags("Authentication");

        group.MapPost("/login", async (
            [FromBody] LoginRequest request,
            AppDbContext db,
            JwtTokenService jwtService,
            CancellationToken cancellationToken) =>
        {
            var user = await db.Users
                .IgnoreQueryFilters()
                .FirstOrDefaultAsync(u => u.Email == request.Email, cancellationToken);

            if (user == null || !PasswordHasher.VerifyPassword(request.Password, user.PasswordHash))
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status401Unauthorized,
                    title: "Unauthorized",
                    detail: "Invalid email or password");
            }

            var token = jwtService.GenerateToken(user);

            return Results.Ok(new LoginResponse
            {
                AccessToken = token,
                TokenType = "Bearer",
                ExpiresIn = 28800,
                UserId = user.Id,
                TenantId = user.TenantId,
                Role = user.Role,
                Email = user.Email,
                Name = user.Name
            });
        }).AllowAnonymous();

        group.MapPost("/api-keys", async (
            [FromBody] CreateApiKeyRequest request,
            ITenantContext tenantContext,
            ApiKeyService apiKeyService,
            HttpContext httpContext) =>
        {
            if (httpContext.User.IsInRole(nameof(UserRole.Auditor)))
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status403Forbidden,
                    title: "Forbidden",
                    detail: "Auditors cannot generate API keys");
            }

            var tenantId = tenantContext.CurrentTenantId;
            if (!tenantId.HasValue)
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status401Unauthorized,
                    title: "Unauthorized",
                    detail: "Tenant context not found");
            }

            var (rawKey, apiKey) = await apiKeyService.CreateApiKeyAsync(
                tenantId.Value,
                request.Name,
                request.Role,
                request.ExpiresInDays);

            return Results.Created($"/api/v1/auth/api-keys/{apiKey.Id}", new ApiKeyResponse
            {
                Id = apiKey.Id,
                Name = apiKey.Name,
                Prefix = apiKey.Prefix,
                RawApiKey = rawKey,
                Role = apiKey.Role,
                CreatedAt = apiKey.CreatedAt,
                ExpiresAt = apiKey.ExpiresAt
            });
        }).RequireAuthorization();
    }
}
