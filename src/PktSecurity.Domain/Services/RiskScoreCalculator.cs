using PktSecurity.Domain.Enums;

namespace PktSecurity.Domain.Services;

public record RiskScoreBreakdown(
    double FinalScore,
    double BaseSeverityScore,
    double ThreatScore,
    double ReachabilityScore,
    double AssetMultiplier,
    IReadOnlyList<string> MissingInputs);

public static class RiskScoreCalculator
{
    public static RiskScoreBreakdown Calculate(
        FindingSeverity severity,
        bool isKev,
        double? epssScore,
        Reachability reachability,
        BusinessCriticality criticality,
        bool isInternetFacing,
        double? cvssScore = null)
    {
        return Calculate(severity, (bool?)isKev, epssScore, reachability, criticality, isInternetFacing, cvssScore);
    }

    public static RiskScoreBreakdown Calculate(
        FindingSeverity severity,
        bool? isKev,
        double? epssScore,
        Reachability reachability,
        BusinessCriticality criticality,
        bool isInternetFacing,
        double? cvssScore = null)
    {
        var missingInputs = new List<string>();

        // 1. Base Severity Score (Max 40.0)
        double baseScore;
        if (cvssScore.HasValue)
        {
            // Scale CVSS 0.0-10.0 to 0.0-40.0
            baseScore = Math.Clamp(cvssScore.Value * 4.0, 0.0, 40.0);
        }
        else
        {
            missingInputs.Add("CVSS");
            baseScore = severity switch
            {
                FindingSeverity.Critical => 40.0,
                FindingSeverity.High => 30.0,
                FindingSeverity.Medium => 20.0,
                FindingSeverity.Low => 10.0,
                FindingSeverity.Info => 0.0,
                _ => 15.0
            };
        }

        // 2. Threat Intelligence Score (Max 30.0: KEV +20, EPSS up to 10)
        double threatScore = 0.0;
        if (isKev.HasValue)
        {
            if (isKev.Value)
            {
                threatScore += 20.0;
            }
        }
        else
        {
            missingInputs.Add("KEV");
        }

        if (epssScore.HasValue)
        {
            threatScore += Math.Clamp(epssScore.Value * 10.0, 0.0, 10.0);
        }
        else
        {
            missingInputs.Add("EPSS");
        }

        // 3. Reachability Score (Max 20.0)
        double reachabilityScore = reachability switch
        {
            Reachability.Reachable => 20.0,
            Reachability.PotentiallyReachable => 10.0,
            Reachability.NoPathFound => 2.0,
            Reachability.Unknown => 0.0,
            _ => 0.0
        };

        if (reachability == Reachability.Unknown)
        {
            missingInputs.Add("Reachability");
        }

        // 4. Asset Context Multiplier
        double assetMultiplier = criticality switch
        {
            BusinessCriticality.Critical => 1.30,
            BusinessCriticality.High => 1.15,
            BusinessCriticality.Medium => 1.00,
            BusinessCriticality.Low => 0.85,
            _ => 1.00
        };

        if (isInternetFacing)
        {
            assetMultiplier *= 1.20;
        }

        var unscaledSum = baseScore + threatScore + reachabilityScore;
        var finalScore = Math.Round(Math.Clamp(unscaledSum * assetMultiplier, 0.0, 100.0), 2);

        return new RiskScoreBreakdown(
            finalScore,
            baseScore,
            threatScore,
            reachabilityScore,
            assetMultiplier,
            missingInputs);
    }
}
