using FluentAssertions;
using PktSecurity.Domain.Services;
using Xunit;

namespace PktSecurity.UnitTests;

public class AuditHashCalculatorTests
{
    [Fact]
    public void ComputeEventHash_ShouldBeDeterministicAndTamperEvident()
    {
        var prevHash = "0000000000000000000000000000000000000000000000000000000000000000";
        var tenantId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var now = DateTime.UtcNow;

        var hash1 = AuditHashCalculator.ComputeEventHash(
            prevHash, tenantId, "SCAN_COMPLETED", userId, "ScanFinished", "{\"findings\":5}", now);

        var hash2 = AuditHashCalculator.ComputeEventHash(
            prevHash, tenantId, "SCAN_COMPLETED", userId, "ScanFinished", "{\"findings\":5}", now);

        hash1.Should().Be(hash2);

        // Tamper with details
        var tamperedHash = AuditHashCalculator.ComputeEventHash(
            prevHash, tenantId, "SCAN_COMPLETED", userId, "ScanFinished", "{\"findings\":0}", now);

        tamperedHash.Should().NotBe(hash1, "Tampered payload must produce a different hash");
    }
}
