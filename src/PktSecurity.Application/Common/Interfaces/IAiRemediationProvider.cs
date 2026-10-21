using PktSecurity.Application.DTOs;

namespace PktSecurity.Application.Common.Interfaces;

public interface IAiRemediationProvider
{
    string ProviderName { get; }
    Task<RemediationSuggestion> GenerateRemediationAsync(
        RemediationContext context,
        CancellationToken cancellationToken = default);
}
