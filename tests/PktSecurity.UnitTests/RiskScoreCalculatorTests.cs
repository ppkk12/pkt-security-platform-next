using FluentAssertions;
using PktSecurity.Domain.Enums;
using PktSecurity.Domain.Services;
using Xunit;

namespace PktSecurity.UnitTests;

public class RiskScoreCalculatorTests
{
    [Fact]
    public void Calculate_WithCriticalInputs_ShouldBeHighAndBoundedTo100()
    {
        var result = RiskScoreCalculator.Calculate(
            severity: FindingSeverity.Critical,
            isKev: true,
            epssScore: 0.95,
            reachability: Reachability.Reachable,
            criticality: BusinessCriticality.Critical,
            isInternetFacing: true,
            cvssScore: 9.8);

        result.FinalScore.Should().BeInRange(0.0, 100.0);
        result.FinalScore.Should().Be(100.0, "Critical + KEV + High EPSS + Reachable + Critical Asset should reach max cap 100.0");
        result.MissingInputs.Should().BeEmpty();
    }

    [Fact]
    public void Calculate_WithMissingInputs_ShouldNotGuessValuesAndRecordMissing()
    {
        var result = RiskScoreCalculator.Calculate(
            severity: FindingSeverity.Medium,
            isKev: false,
            epssScore: null,
            reachability: Reachability.Unknown,
            criticality: BusinessCriticality.Medium,
            isInternetFacing: false,
            cvssScore: null);

        result.FinalScore.Should().BeInRange(0.0, 100.0);
        result.MissingInputs.Should().Contain("CVSS");
        result.MissingInputs.Should().Contain("EPSS");
        result.MissingInputs.Should().Contain("Reachability");
    }

    [Fact]
    public void Calculate_KevAdds20Points()
    {
        var withoutKev = RiskScoreCalculator.Calculate(
            severity: FindingSeverity.High,
            isKev: false,
            epssScore: 0.5,
            reachability: Reachability.PotentiallyReachable,
            criticality: BusinessCriticality.Medium,
            isInternetFacing: false);

        var withKev = RiskScoreCalculator.Calculate(
            severity: FindingSeverity.High,
            isKev: true,
            epssScore: 0.5,
            reachability: Reachability.PotentiallyReachable,
            criticality: BusinessCriticality.Medium,
            isInternetFacing: false);

        (withKev.ThreatScore - withoutKev.ThreatScore).Should().Be(20.0, "KEV flag must add exactly 20.0 threat points");
    }

    [Fact]
    public void Calculate_WhenKevIsNull_ShouldRecordKevInMissingInputsAndNotAddPoints()
    {
        var result = RiskScoreCalculator.Calculate(
            severity: FindingSeverity.Medium,
            isKev: (bool?)null,
            epssScore: null,
            reachability: Reachability.Unknown,
            criticality: BusinessCriticality.Medium,
            isInternetFacing: false,
            cvssScore: null);

        result.MissingInputs.Should().Contain("KEV");
        result.MissingInputs.Should().Contain("CVSS");
        result.MissingInputs.Should().Contain("EPSS");
        result.MissingInputs.Should().Contain("Reachability");
        result.ThreatScore.Should().Be(0.0, "Threat score must remain 0 when KEV is null and EPSS is null (no guessing allowed)");
    }
}
