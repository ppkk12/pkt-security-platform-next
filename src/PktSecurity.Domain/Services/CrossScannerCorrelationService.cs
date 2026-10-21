using PktSecurity.Domain.Entities;
using PktSecurity.Domain.Enums;

namespace PktSecurity.Domain.Services;

public static class CrossScannerCorrelationService
{
    public static int CorrelateFindings(IList<Finding> findings)
    {
        int correlatedPairs = 0;

        for (int i = 0; i < findings.Count; i++)
        {
            var f1 = findings[i];

            for (int j = i + 1; j < findings.Count; j++)
            {
                var f2 = findings[j];

                // Must be from different scanners
                if (string.Equals(f1.ScannerName, f2.ScannerName, StringComparison.OrdinalIgnoreCase))
                    continue;

                if (IsCorrelated(f1, f2))
                {
                    correlatedPairs++;

                    // Unify or assign CorrelationGroupId
                    if (f1.CorrelationGroupId.HasValue && f2.CorrelationGroupId.HasValue)
                    {
                        if (f1.CorrelationGroupId != f2.CorrelationGroupId)
                        {
                            var targetId = f1.CorrelationGroupId.Value;
                            var oldId = f2.CorrelationGroupId.Value;
                            foreach (var f in findings)
                            {
                                if (f.CorrelationGroupId == oldId)
                                    f.CorrelationGroupId = targetId;
                            }
                        }
                    }
                    else if (f1.CorrelationGroupId.HasValue)
                    {
                        f2.CorrelationGroupId = f1.CorrelationGroupId;
                    }
                    else if (f2.CorrelationGroupId.HasValue)
                    {
                        f1.CorrelationGroupId = f2.CorrelationGroupId;
                    }
                    else
                    {
                        var newGroupId = Guid.NewGuid();
                        f1.CorrelationGroupId = newGroupId;
                        f2.CorrelationGroupId = newGroupId;
                    }

                    // Boost confidence to High (1.0)
                    f1.Confidence = 1.0;
                    f2.Confidence = 1.0;
                }
            }
        }

        return correlatedPairs;
    }

    public static bool IsCorrelated(Finding f1, Finding f2)
    {
        // 1. SCA Match: Identical Package PURL + Identical CVE
        if (!string.IsNullOrWhiteSpace(f1.PackagePurl) &&
            !string.IsNullOrWhiteSpace(f2.PackagePurl) &&
            string.Equals(f1.PackagePurl, f2.PackagePurl, StringComparison.OrdinalIgnoreCase))
        {
            if (!string.IsNullOrWhiteSpace(f1.CveId) &&
                !string.IsNullOrWhiteSpace(f2.CveId) &&
                string.Equals(f1.CveId, f2.CveId, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        // 2. SAST / Code Match: Identical File Path + Identical CWE
        if (!string.IsNullOrWhiteSpace(f1.FilePath) &&
            !string.IsNullOrWhiteSpace(f2.FilePath))
        {
            var normPath1 = f1.FilePath.Replace('\\', '/').Trim().ToLowerInvariant();
            var normPath2 = f2.FilePath.Replace('\\', '/').Trim().ToLowerInvariant();

            if (normPath1 == normPath2)
            {
                if (!string.IsNullOrWhiteSpace(f1.CweId) &&
                    !string.IsNullOrWhiteSpace(f2.CweId) &&
                    string.Equals(f1.CweId, f2.CweId, StringComparison.OrdinalIgnoreCase))
                {
                    // Match enclosing symbol if present
                    if (!string.IsNullOrWhiteSpace(f1.EnclosingSymbol) &&
                        !string.IsNullOrWhiteSpace(f2.EnclosingSymbol) &&
                        string.Equals(f1.EnclosingSymbol.Trim(), f2.EnclosingSymbol.Trim(), StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }

                    // Or close line proximity (within 15 lines)
                    if (f1.StartLine.HasValue && f2.StartLine.HasValue)
                    {
                        if (Math.Abs(f1.StartLine.Value - f2.StartLine.Value) <= 15)
                        {
                            return true;
                        }
                    }
                    else if (!f1.StartLine.HasValue && !f2.StartLine.HasValue)
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }
}
