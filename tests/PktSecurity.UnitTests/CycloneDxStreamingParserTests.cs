using System.Text;
using FluentAssertions;
using PktSecurity.Infrastructure.Parsers;
using Xunit;

namespace PktSecurity.UnitTests;

public class CycloneDxStreamingParserTests
{
    [Fact]
    public async Task ParseAsync_WithValidCycloneDx16_ShouldExtractComponentsAndMetadata()
    {
        var sampleJson = @"
{
  ""bomFormat"": ""CycloneDX"",
  ""specVersion"": ""1.6"",
  ""serialNumber"": ""urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"",
  ""version"": 1,
  ""metadata"": {
    ""component"": {
      ""name"": ""my-application"",
      ""version"": ""1.0.0"",
      ""purl"": ""pkg:npm/my-application@1.0.0""
    }
  },
  ""components"": [
    {
      ""name"": ""lodash"",
      ""version"": ""4.17.20"",
      ""purl"": ""pkg:npm/lodash@4.17.20"",
      ""licenses"": [
        {
          ""license"": {
            ""id"": ""MIT""
          }
        }
      ]
    },
    {
      ""name"": ""requests"",
      ""version"": ""2.25.0"",
      ""purl"": ""pkg:pypi/requests@2.25.0"",
      ""licenses"": [
        {
          ""license"": {
            ""id"": ""Apache-2.0""
          }
        }
      ]
    }
  ],
  ""dependencies"": [
    {
      ""ref"": ""pkg:npm/my-application@1.0.0"",
      ""dependsOn"": [
        ""pkg:npm/lodash@4.17.20""
      ]
    }
  ]
}";

        var parser = new CycloneDxStreamingParser();
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(sampleJson));

        var bom = await parser.ParseAsync(stream);

        bom.Should().NotBeNull();
        bom.SpecVersion.Should().Be("1.6");
        bom.SerialNumber.Should().Be("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79");
        bom.Version.Should().Be(1);
        bom.Components.Should().HaveCount(2);

        var lodash = bom.Components.FirstOrDefault(c => c.Name == "lodash");
        lodash.Should().NotBeNull();
        lodash!.Version.Should().Be("4.17.20");
        lodash.Purl.Should().Be("pkg:npm/lodash@4.17.20");
        lodash.License.Should().Be("MIT");

        bom.Dependencies.Should().HaveCount(1);
        bom.Dependencies[0].DependsOn.Should().Contain("pkg:npm/lodash@4.17.20");
    }
}
