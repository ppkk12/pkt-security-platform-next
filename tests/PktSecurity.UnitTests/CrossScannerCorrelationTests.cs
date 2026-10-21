using FluentAssertions;
using PktSecurity.Domain.Entities;
using PktSecurity.Domain.Enums;
using PktSecurity.Domain.Services;
using Xunit;

namespace PktSecurity.UnitTests;

public class CrossScannerCorrelationTests
{
    [Fact]
    public void CorrelateFindings_ScaMatchAcrossDifferentScanners_ShouldAssignSameCorrelationGroupIdAndBoostConfidence()
    {
        var projectId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();

        var finding1 = new Finding
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            ProjectId = projectId,
            ScannerName = "trivy",
            Category = FindingCategory.SCA,
            PackagePurl = "pkg:npm/lodash@4.17.20",
            CveId = "CVE-2021-23337",
            Confidence = 0.8,
            CorrelationGroupId = null
        };

        var finding2 = new Finding
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            ProjectId = projectId,
            ScannerName = "native-sca",
            Category = FindingCategory.SCA,
            PackagePurl = "pkg:npm/lodash@4.17.20",
            CveId = "CVE-2021-23337",
            Confidence = 0.85,
            CorrelationGroupId = null
        };

        var findings = new List<Finding> { finding1, finding2 };
        var correlatedPairs = CrossScannerCorrelationService.CorrelateFindings(findings);

        correlatedPairs.Should().Be(1);
        finding1.CorrelationGroupId.Should().NotBeNull();
        finding2.CorrelationGroupId.Should().NotBeNull();
        finding1.CorrelationGroupId.Should().Be(finding2.CorrelationGroupId);
        finding1.Confidence.Should().Be(1.0);
        finding2.Confidence.Should().Be(1.0);
    }

    [Fact]
    public void CorrelateFindings_SastMatchCloseLines_ShouldAssignSameCorrelationGroupId()
    {
        var projectId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();

        var finding1 = new Finding
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            ProjectId = projectId,
            ScannerName = "semgrep",
            Category = FindingCategory.SAST,
            FilePath = "src/app.py",
            CweId = "CWE-89",
            StartLine = 20,
            Confidence = 0.7
        };

        var finding2 = new Finding
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            ProjectId = projectId,
            ScannerName = "native-sast",
            Category = FindingCategory.SAST,
            FilePath = "src/app.py",
            CweId = "CWE-89",
            StartLine = 24, // within 15 lines
            Confidence = 0.9
        };

        var findings = new List<Finding> { finding1, finding2 };
        var correlatedPairs = CrossScannerCorrelationService.CorrelateFindings(findings);

        correlatedPairs.Should().Be(1);
        finding1.CorrelationGroupId.Should().Be(finding2.CorrelationGroupId);
        finding1.Confidence.Should().Be(1.0);
        finding2.Confidence.Should().Be(1.0);
    }

    [Fact]
    public void CorrelateFindings_SameScanner_ShouldNotCorrelate()
    {
        var projectId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();

        var finding1 = new Finding
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            ProjectId = projectId,
            ScannerName = "native-sast",
            Category = FindingCategory.SAST,
            FilePath = "src/app.py",
            CweId = "CWE-89",
            StartLine = 20
        };

        var finding2 = new Finding
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            ProjectId = projectId,
            ScannerName = "native-sast", // same scanner
            Category = FindingCategory.SAST,
            FilePath = "src/app.py",
            CweId = "CWE-89",
            StartLine = 22
        };

        var findings = new List<Finding> { finding1, finding2 };
        var correlatedPairs = CrossScannerCorrelationService.CorrelateFindings(findings);

        correlatedPairs.Should().Be(0);
        finding1.CorrelationGroupId.Should().BeNull();
        finding2.CorrelationGroupId.Should().BeNull();
    }
}
