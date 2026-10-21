using FluentAssertions;
using Microsoft.Extensions.Options;
using PktSecurity.Application.Common.Interfaces;
using PktSecurity.Infrastructure.Sandbox;
using Xunit;

namespace PktSecurity.UnitTests;

public class DockerSandboxExecutionProviderTests
{
    [Fact]
    public void BuildDockerArguments_DefaultOptions_MustIncludeAllSecurityIsolationFlags()
    {
        // Arrange
        var provider = new DockerSandboxExecutionProvider();
        var request = new SandboxExecutionRequest(
            ExecutablePath: "trivy",
            Arguments: new[] { "fs", "--format", "sarif", "/workspace" },
            WorkingDirectory: "C:\\test\\workspace",
            Timeout: TimeSpan.FromMinutes(2));

        // Act
        var args = provider.BuildDockerArguments(request);

        // Assert
        args.Should().Contain("run");
        args.Should().Contain("--rm");
        args.Should().Contain("--network=none", "Network access must be disabled");
        args.Should().Contain("--read-only", "Root filesystem must be mounted read-only");
        args.Should().Contain("--cap-drop=ALL", "All Linux capabilities must be dropped");
        args.Should().Contain("--security-opt=no-new-privileges", "Privilege escalation must be blocked");
        args.Should().Contain("--pids-limit=256", "Fork bomb mitigation must be enforced");
        args.Should().Contain("--memory=2g", "Memory limit must default to 2g");
        args.Should().Contain("--cpus=2", "CPU limit must default to 2 cores");

        // Temporary storage
        args.Should().Contain("--tmpfs");
        args.Should().Contain("/tmp:rw,noexec,nosuid,size=512m");

        // Working directory mount
        args.Should().Contain("-v");
        args.Should().ContainMatch("*:ro", "Workspace must be mounted read-only");
        args.Should().Contain("-w");
        args.Should().Contain("/workspace");

        // Executable & trailing arguments
        args.Should().Contain("trivy");
        args.Should().Contain("sarif");
    }

    [Fact]
    public void BuildDockerArguments_WithGvisorEnabled_MustIncludeRuntimeRunsc()
    {
        // Arrange
        var options = Options.Create(new DockerSandboxOptions
        {
            EnableGvisor = true,
            Image = "custom-runner:1.0"
        });
        var provider = new DockerSandboxExecutionProvider(options);
        var request = new SandboxExecutionRequest(
            ExecutablePath: "semgrep",
            Arguments: new[] { "scan", "--json" },
            WorkingDirectory: "C:\\test\\workspace",
            Timeout: TimeSpan.FromMinutes(2));

        // Act
        var args = provider.BuildDockerArguments(request);

        // Assert
        args.Should().Contain("--runtime=runsc", "gVisor sandboxed runtime flag must be passed when enabled");
        args.Should().Contain("custom-runner:1.0");
        args.Should().Contain("semgrep");
    }

    [Fact]
    public void BuildDockerArguments_WithCustomLimitsAndEnv_MustApplyCorrectly()
    {
        // Arrange
        var options = Options.Create(new DockerSandboxOptions
        {
            CpuLimit = "4",
            PidsLimit = 512
        });
        var provider = new DockerSandboxExecutionProvider(options);
        var envVars = new Dictionary<string, string>
        {
            ["SCANNER_MODE"] = "fast",
            ["CI"] = "true"
        };
        var request = new SandboxExecutionRequest(
            ExecutablePath: "gitleaks",
            Arguments: new[] { "detect" },
            WorkingDirectory: "C:\\test\\workspace",
            Timeout: TimeSpan.FromMinutes(2),
            EnvironmentVariables: envVars,
            MemoryLimitMb: 4096);

        // Act
        var args = provider.BuildDockerArguments(request);

        // Assert
        args.Should().Contain("--memory=4096m");
        args.Should().Contain("--cpus=4");
        args.Should().Contain("--pids-limit=512");
        args.Should().Contain("-e");
        args.Should().Contain("SCANNER_MODE=fast");
        args.Should().Contain("CI=true");
    }
}
