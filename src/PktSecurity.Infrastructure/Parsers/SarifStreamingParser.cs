using System.Text.Json;
using PktSecurity.Application.DTOs;
using PktSecurity.Domain.Enums;

namespace PktSecurity.Infrastructure.Parsers;

public class SarifStreamingParser
{
    public async IAsyncEnumerable<NormalizedFindingDto> ParseAsync(
        Stream stream,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
        var root = document.RootElement;

        if (!root.TryGetProperty("runs", out var runsElement) || runsElement.ValueKind != JsonValueKind.Array)
        {
            yield break;
        }

        foreach (var run in runsElement.EnumerateArray())
        {
            var toolName = "UnknownScanner";
            var rulesDict = new Dictionary<string, (string name, string? cwe, FindingSeverity severity)>(StringComparer.OrdinalIgnoreCase);

            if (run.TryGetProperty("tool", out var tool) && tool.TryGetProperty("driver", out var driver))
            {
                if (driver.TryGetProperty("name", out var driverName))
                {
                    toolName = driverName.GetString() ?? toolName;
                }

                if (driver.TryGetProperty("rules", out var rules) && rules.ValueKind == JsonValueKind.Array)
                {
                    foreach (var rule in rules.EnumerateArray())
                    {
                        var ruleId = rule.TryGetProperty("id", out var idProp) ? idProp.GetString() : null;
                        if (string.IsNullOrEmpty(ruleId)) continue;

                        var ruleName = rule.TryGetProperty("name", out var nameProp) ? nameProp.GetString() : ruleId;
                        string? cwe = null;
                        var defaultSev = FindingSeverity.Medium;

                        if (rule.TryGetProperty("properties", out var props))
                        {
                            if (props.TryGetProperty("tags", out var tags) && tags.ValueKind == JsonValueKind.Array)
                            {
                                foreach (var tag in tags.EnumerateArray())
                                {
                                    var tagStr = tag.GetString() ?? string.Empty;
                                    if (tagStr.StartsWith("CWE-", StringComparison.OrdinalIgnoreCase))
                                    {
                                        cwe = tagStr;
                                        break;
                                    }
                                }
                            }
                        }

                        rulesDict[ruleId] = (ruleName ?? ruleId, cwe, defaultSev);
                    }
                }
            }

            if (!run.TryGetProperty("results", out var results) || results.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var result in results.EnumerateArray())
            {
                cancellationToken.ThrowIfCancellationRequested();

                var ruleId = result.TryGetProperty("ruleId", out var rId) ? rId.GetString() : "UNKNOWN";
                var message = string.Empty;
                if (result.TryGetProperty("message", out var msgProp) && msgProp.TryGetProperty("text", out var textProp))
                {
                    message = textProp.GetString() ?? string.Empty;
                }

                var level = result.TryGetProperty("level", out var lvlProp) ? lvlProp.GetString() : "warning";
                var severity = MapSarifLevelToSeverity(level);

                string? filePath = null;
                int? startLine = null;
                int? endLine = null;
                string? snippet = null;

                if (result.TryGetProperty("locations", out var locations) &&
                    locations.ValueKind == JsonValueKind.Array &&
                    locations.GetArrayLength() > 0)
                {
                    var firstLoc = locations[0];
                    if (firstLoc.TryGetProperty("physicalLocation", out var physLoc))
                    {
                        if (physLoc.TryGetProperty("artifactLocation", out var artLoc) &&
                            artLoc.TryGetProperty("uri", out var uriProp))
                        {
                            filePath = uriProp.GetString();
                        }

                        if (physLoc.TryGetProperty("region", out var region))
                        {
                            if (region.TryGetProperty("startLine", out var sl)) startLine = sl.GetInt32();
                            if (region.TryGetProperty("endLine", out var el)) endLine = el.GetInt32();
                            if (region.TryGetProperty("snippet", out var snip) && snip.TryGetProperty("text", out var st))
                            {
                                snippet = st.GetString();
                            }
                        }
                    }
                }

                string? cweId = null;
                string? cveId = null;

                if (ruleId != null && rulesDict.TryGetValue(ruleId, out var ruleInfo))
                {
                    cweId = ruleInfo.cwe;
                }

                if (ruleId != null && ruleId.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase))
                {
                    cveId = ruleId;
                }

                var category = DetermineCategory(toolName, ruleId);

                var dto = new NormalizedFindingDto
                {
                    Title = string.IsNullOrWhiteSpace(message) ? (ruleId ?? "Security Finding") : message.Split('\n')[0].Trim(),
                    Description = message,
                    Severity = severity,
                    Category = category,
                    ScannerName = toolName,
                    RuleId = ruleId,
                    CweId = cweId,
                    CveId = cveId,
                    FilePath = filePath,
                    StartLine = startLine,
                    EndLine = endLine,
                    CodeSnippet = snippet,
                    RawResultJson = result.GetRawText(),
                    IsKev = false,
                    Reachability = Reachability.Unknown
                };

                yield return dto;
            }
        }
    }

    private static FindingSeverity MapSarifLevelToSeverity(string? level)
    {
        return (level?.ToLowerInvariant()) switch
        {
            "error" => FindingSeverity.High,
            "warning" => FindingSeverity.Medium,
            "note" => FindingSeverity.Low,
            "none" => FindingSeverity.Info,
            _ => FindingSeverity.Medium
        };
    }

    private static FindingCategory DetermineCategory(string toolName, string? ruleId)
    {
        var lower = toolName.ToLowerInvariant();
        if (lower.Contains("gitleaks") || lower.Contains("secret")) return FindingCategory.Secret;
        if (lower.Contains("trivy") || lower.Contains("grype") || lower.Contains("osv")) return FindingCategory.SCA;
        if (lower.Contains("semgrep") || lower.Contains("codeql")) return FindingCategory.SAST;
        return FindingCategory.SAST;
    }
}
