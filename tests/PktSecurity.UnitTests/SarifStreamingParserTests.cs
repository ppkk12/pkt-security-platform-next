using System.Text;
using FluentAssertions;
using PktSecurity.Domain.Enums;
using PktSecurity.Infrastructure.Parsers;
using Xunit;

namespace PktSecurity.UnitTests;

public class SarifStreamingParserTests
{
    [Fact]
    public async Task ParseAsync_ShouldStreamFindingsCorrectly()
    {
        var parser = new SarifStreamingParser();

        var sarifJson = @"{
          ""version"": ""2.1.0"",
          ""runs"": [
            {
              ""tool"": {
                ""driver"": {
                  ""name"": ""trivy"",
                  ""rules"": [
                    {
                      ""id"": ""CVE-2021-23337"",
                      ""properties"": {
                        ""tags"": [""CWE-78""]
                      }
                    }
                  ]
                }
              },
              ""results"": [
                {
                  ""ruleId"": ""CVE-2021-23337"",
                  ""level"": ""error"",
                  ""message"": { ""text"": ""lodash: Command Injection via template function"" },
                  ""locations"": [
                    {
                      ""physicalLocation"": {
                        ""artifactLocation"": { ""uri"": ""package-lock.json"" },
                        ""region"": {
                          ""startLine"": 12,
                          ""endLine"": 14,
                          ""snippet"": { ""text"": ""\""lodash\"": { \""version\"": \""4.17.20\"" }"" }
                        }
                      }
                    }
                  ]
                }
              ]
            }
          ]
        }";

        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(sarifJson));
        var findings = new List<Application.DTOs.NormalizedFindingDto>();

        await foreach (var item in parser.ParseAsync(stream))
        {
            findings.Add(item);
        }

        findings.Should().HaveCount(1);
        var f = findings[0];
        f.RuleId.Should().Be("CVE-2021-23337");
        f.CweId.Should().Be("CWE-78");
        f.Severity.Should().Be(FindingSeverity.High);
        f.FilePath.Should().Be("package-lock.json");
        f.StartLine.Should().Be(12);
        f.CodeSnippet.Should().Contain("lodash");
    }
}
