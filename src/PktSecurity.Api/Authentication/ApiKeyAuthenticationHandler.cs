using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using PktSecurity.Infrastructure.Security;

namespace PktSecurity.Api.Authentication;

public class ApiKeyAuthenticationOptions : AuthenticationSchemeOptions
{
}

public class ApiKeyAuthenticationHandler : AuthenticationHandler<ApiKeyAuthenticationOptions>
{
    public const string SchemeName = "ApiKey";
    private readonly ApiKeyService _apiKeyService;

    public ApiKeyAuthenticationHandler(
        IOptionsMonitor<ApiKeyAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ApiKeyService apiKeyService)
        : base(options, logger, encoder)
    {
        _apiKeyService = apiKeyService;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        string? rawApiKey = null;

        if (Request.Headers.TryGetValue("X-API-Key", out var apiKeyHeader))
        {
            rawApiKey = apiKeyHeader.ToString();
        }
        else if (Request.Headers.TryGetValue("Authorization", out var authHeader))
        {
            var authStr = authHeader.ToString();
            if (authStr.StartsWith("Bearer pkt_live_", StringComparison.OrdinalIgnoreCase))
            {
                rawApiKey = authStr["Bearer ".Length..].Trim();
            }
        }

        if (string.IsNullOrWhiteSpace(rawApiKey))
        {
            return AuthenticateResult.NoResult();
        }

        var key = await _apiKeyService.ValidateApiKeyAsync(rawApiKey);
        if (key == null)
        {
            return AuthenticateResult.Fail("Invalid or expired API key");
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, key.Id.ToString()),
            new("tenant_id", key.TenantId.ToString()),
            new(ClaimTypes.Role, key.Role.ToString()),
            new(ClaimTypes.Name, key.Name),
            new("auth_type", "api_key")
        };

        var identity = new ClaimsIdentity(claims, SchemeName);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, SchemeName);

        return AuthenticateResult.Success(ticket);
    }
}
