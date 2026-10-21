using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using PktSecurity.Application.Common.Interfaces;
using PktSecurity.Application.DTOs;
using PktSecurity.Infrastructure.Security;

namespace PktSecurity.Infrastructure.Services;

public class LlmAiRemediationProvider : IAiRemediationProvider
{
    private readonly HttpClient _httpClient;
    private readonly IConfiguration _configuration;
    private readonly ILogger<LlmAiRemediationProvider> _logger;
    private readonly RuleBasedRemediationProvider _fallbackProvider;

    public string ProviderName => "LLM";

    public LlmAiRemediationProvider(
        HttpClient httpClient,
        IConfiguration configuration,
        ILogger<LlmAiRemediationProvider> logger,
        RuleBasedRemediationProvider fallbackProvider)
    {
        _httpClient = httpClient;
        _configuration = configuration;
        _logger = logger;
        _fallbackProvider = fallbackProvider;
    }

    public async Task<RemediationSuggestion> GenerateRemediationAsync(
        RemediationContext context,
        CancellationToken cancellationToken = default)
    {
        var apiKey = _configuration["AI:ApiKey"];
        var endpoint = _configuration["AI:Endpoint"];

        // If no API key or endpoint configured, seamlessly use deterministic rule-based generator
        if (string.IsNullOrWhiteSpace(apiKey) && string.IsNullOrWhiteSpace(endpoint))
        {
            _logger.LogInformation("No external LLM credentials configured. Using deterministic rule-based remediation provider for finding {FindingId}", context.FindingId);
            return await _fallbackProvider.GenerateRemediationAsync(context, cancellationToken);
        }

        try
        {
            // Protect against prompt injection using random boundary tokens
            var rawSnippet = context.CodeSnippet ?? context.FullFileContent ?? $"Vulnerability in {context.FilePath}:{context.StartLine}";
            var (boundaryToken, wrappedCode) = AiPromptDefense.WrapUntrustedCode(rawSnippet);

            var systemPrompt = AiPromptDefense.BuildSystemPrompt(boundaryToken);
            var userPrompt = $@"Generate a remediation for finding:
Title: {context.Title}
Scanner: {context.ScannerName}
CWE: {context.CweId}
CVE: {context.CveId}
Target File: {context.FilePath}
Line: {context.StartLine}

Target code:
{wrappedCode}";

            var requestBody = new
            {
                model = _configuration["AI:Model"] ?? "gpt-4o-mini",
                messages = new[]
                {
                    new { role = "system", content = systemPrompt },
                    new { role = "user", content = userPrompt }
                },
                temperature = 0.1,
                response_format = new { type = "json_object" }
            };

            var response = await _httpClient.PostAsJsonAsync(endpoint ?? "https://api.openai.com/v1/chat/completions", requestBody, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("LLM request failed with status {StatusCode}. Falling back to rule-based remediation", response.StatusCode);
                return await _fallbackProvider.GenerateRemediationAsync(context, cancellationToken);
            }

            var jsonResp = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: cancellationToken);
            var contentStr = jsonResp.GetProperty("choices")[0].GetProperty("message").GetProperty("content").GetString();

            if (string.IsNullOrEmpty(contentStr))
            {
                return await _fallbackProvider.GenerateRemediationAsync(context, cancellationToken);
            }

            var parsed = JsonSerializer.Deserialize<RemediationSuggestion>(contentStr, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (parsed == null || string.IsNullOrWhiteSpace(parsed.ProposedUnifiedDiff))
            {
                return await _fallbackProvider.GenerateRemediationAsync(context, cancellationToken);
            }

            // Verify proposed diff path security
            AiPromptDefense.ValidateDiff(parsed.ProposedUnifiedDiff, context.FilePath);

            return parsed;
        }
        catch (SecurityViolationException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to generate LLM remediation for finding {FindingId}. Falling back to rule-based provider", context.FindingId);
            return await _fallbackProvider.GenerateRemediationAsync(context, cancellationToken);
        }
    }
}
