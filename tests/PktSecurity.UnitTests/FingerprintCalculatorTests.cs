using FluentAssertions;
using PktSecurity.Domain.Services;
using Xunit;

namespace PktSecurity.UnitTests;

public class FingerprintCalculatorTests
{
    [Fact]
    public void PrimaryFingerprint_ShouldBeDeterministic()
    {
        var fp1 = FingerprintCalculator.ComputePrimary("trivy", "CVE-2021-23337", "src/package-lock.json", 12);
        var fp2 = FingerprintCalculator.ComputePrimary("TRIVY", "CVE-2021-23337", "src\\package-lock.json", 12);

        fp1.Should().NotBeNullOrWhiteSpace();
        fp1.Should().Be(fp2, "Primary fingerprint must normalize tool casing and path backslashes");
    }

    [Fact]
    public void SecondaryFingerprint_ShouldBeResilientToLineDriftAndComments()
    {
        var tenantId = Guid.NewGuid();
        var projectId = Guid.NewGuid();
        var category = "SAST";
        var cweOrCve = "CWE-89";
        var filePath = "src/Database.cs";
        var symbol = "GetUserById";

        var snippetOriginal = @"
            // Fetch user from DB
            var query = ""SELECT * FROM Users WHERE Id = '"" + userId + ""'"";
            Execute(query);
        ";

        var snippetModifiedWithCommentsAndSpaces = @"
            /* Updated comment with extra spacing */
            var   query   =   ""SELECT * FROM Users WHERE Id = '""  +  userId  +  ""'"";
            // Another inline comment
            Execute(query);
        ";

        var fp1 = FingerprintCalculator.ComputeSecondary(
            tenantId, projectId, category, cweOrCve, filePath, symbol, snippetOriginal);

        var fp2 = FingerprintCalculator.ComputeSecondary(
            tenantId, projectId, category, cweOrCve, filePath, symbol, snippetModifiedWithCommentsAndSpaces);

        fp1.Should().Be(fp2, "Secondary fingerprint must be immune to comment changes and whitespace variations");
    }

    [Fact]
    public void SecondaryFingerprint_ShouldChange_WhenCodeSemanticsDiffer()
    {
        var tenantId = Guid.NewGuid();
        var projectId = Guid.NewGuid();

        var fp1 = FingerprintCalculator.ComputeSecondary(
            tenantId, projectId, "SAST", "CWE-89", "file.cs", "Func1", "var a = 1;");

        var fp2 = FingerprintCalculator.ComputeSecondary(
            tenantId, projectId, "SAST", "CWE-89", "file.cs", "Func1", "var a = 2;");

        fp1.Should().NotBe(fp2, "Different code semantics must yield different secondary fingerprints");
    }

    [Fact]
    public void SecondaryFingerprint_WithTenPrependedCommentLines_ShouldMatch_WhilePrimaryChanges()
    {
        var tenantId = Guid.NewGuid();
        var projectId = Guid.NewGuid();
        var toolName = "native-sast";
        var ruleId = "CWE-89";
        var filePath = "src/Controllers/UserController.cs";
        var symbol = "GetUserById";
        var code = "var q = \"SELECT * FROM users WHERE id = \" + id;";

        // Original location: line 15
        var primary1 = FingerprintCalculator.ComputePrimary(toolName, ruleId, filePath, 15);
        var secondary1 = FingerprintCalculator.ComputeSecondary(tenantId, projectId, "SAST", ruleId, filePath, symbol, code);

        // Prepended 10 comment lines -> shifted to line 25
        var primary2 = FingerprintCalculator.ComputePrimary(toolName, ruleId, filePath, 25);
        var shiftedCodeWithComments = "// Comment 1\n// Comment 2\n\n// Comment 3\n" + code;
        var secondary2 = FingerprintCalculator.ComputeSecondary(tenantId, projectId, "SAST", ruleId, filePath, symbol, shiftedCodeWithComments);

        primary1.Should().NotBe(primary2, "Primary fingerprint must change when line number shifts");
        secondary1.Should().Be(secondary2, "Secondary fingerprint must remain identical despite 10 prepended comments/empty lines");
    }
}
