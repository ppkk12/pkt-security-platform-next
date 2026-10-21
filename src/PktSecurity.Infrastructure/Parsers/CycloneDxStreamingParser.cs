using System.Text.Json;

namespace PktSecurity.Infrastructure.Parsers;

public class ParsedCycloneDxComponent
{
    public string Name { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string Purl { get; set; } = string.Empty;
    public string Type { get; set; } = "library";
    public string? License { get; set; }
    public string? BomRef { get; set; }
}

public class ParsedCycloneDxDependency
{
    public string Ref { get; set; } = string.Empty;
    public List<string> DependsOn { get; set; } = new();
}

public class ParsedCycloneDxBom
{
    public string SpecVersion { get; set; } = "1.6";
    public string? SerialNumber { get; set; }
    public int Version { get; set; } = 1;
    public string? RootComponentRef { get; set; }
    public List<ParsedCycloneDxComponent> Components { get; set; } = new();
    public List<ParsedCycloneDxDependency> Dependencies { get; set; } = new();
}

public class CycloneDxStreamingParser
{
    public async Task<ParsedCycloneDxBom> ParseAsync(
        Stream stream,
        CancellationToken cancellationToken = default)
    {
        using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
        var root = document.RootElement;

        var bom = new ParsedCycloneDxBom();

        if (root.TryGetProperty("specVersion", out var specProp))
        {
            bom.SpecVersion = specProp.GetString() ?? "1.6";
        }

        if (root.TryGetProperty("serialNumber", out var serialProp))
        {
            bom.SerialNumber = serialProp.GetString();
        }

        if (root.TryGetProperty("version", out var verProp) && verProp.TryGetInt32(out var version))
        {
            bom.Version = version;
        }

        if (root.TryGetProperty("metadata", out var metadata))
        {
            if (metadata.TryGetProperty("component", out var rootComp))
            {
                if (rootComp.TryGetProperty("bom-ref", out var bomRef))
                {
                    bom.RootComponentRef = bomRef.GetString();
                }
                else if (rootComp.TryGetProperty("purl", out var rootPurl))
                {
                    bom.RootComponentRef = rootPurl.GetString();
                }
                else if (rootComp.TryGetProperty("name", out var rootName))
                {
                    bom.RootComponentRef = rootName.GetString();
                }
            }
        }

        if (root.TryGetProperty("components", out var componentsElement) && componentsElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var comp in componentsElement.EnumerateArray())
            {
                var name = comp.TryGetProperty("name", out var nProp) ? nProp.GetString() ?? string.Empty : string.Empty;
                var versionStr = comp.TryGetProperty("version", out var vProp) ? vProp.GetString() ?? string.Empty : string.Empty;
                var purl = comp.TryGetProperty("purl", out var pProp) ? pProp.GetString() ?? string.Empty : string.Empty;
                var type = comp.TryGetProperty("type", out var tProp) ? tProp.GetString() ?? "library" : "library";

                if (string.IsNullOrWhiteSpace(purl) && !string.IsNullOrWhiteSpace(name))
                {
                    purl = $"pkg:generic/{name}@{versionStr}";
                }

                string? license = null;
                if (comp.TryGetProperty("licenses", out var licArray) && licArray.ValueKind == JsonValueKind.Array)
                {
                    foreach (var licEntry in licArray.EnumerateArray())
                    {
                        if (licEntry.TryGetProperty("license", out var licObj))
                        {
                            if (licObj.TryGetProperty("id", out var idProp))
                            {
                                license = idProp.GetString();
                                break;
                            }
                            if (licObj.TryGetProperty("name", out var nameProp))
                            {
                                license = nameProp.GetString();
                                break;
                            }
                        }
                    }
                }

                string? bomRef = comp.TryGetProperty("bom-ref", out var brProp) ? brProp.GetString() : null;

                bom.Components.Add(new ParsedCycloneDxComponent
                {
                    Name = name,
                    Version = versionStr,
                    Purl = purl,
                    Type = type,
                    License = license,
                    BomRef = bomRef
                });
            }
        }

        if (root.TryGetProperty("dependencies", out var dependenciesElement) && dependenciesElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var dep in dependenciesElement.EnumerateArray())
            {
                var depRef = dep.TryGetProperty("ref", out var rProp) ? rProp.GetString() ?? string.Empty : string.Empty;
                var depItem = new ParsedCycloneDxDependency { Ref = depRef };

                if (dep.TryGetProperty("dependsOn", out var onProp) && onProp.ValueKind == JsonValueKind.Array)
                {
                    foreach (var d in onProp.EnumerateArray())
                    {
                        var s = d.GetString();
                        if (!string.IsNullOrEmpty(s))
                        {
                            depItem.DependsOn.Add(s);
                        }
                    }
                }

                bom.Dependencies.Add(depItem);
            }
        }

        return bom;
    }
}
