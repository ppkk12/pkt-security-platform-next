using PktSecurity.Domain.Entities;

namespace PktSecurity.Application.Common.Interfaces;

public interface IJobQueueProvider
{
    Task<ScanJob?> DequeueJobAsync(string workerId, CancellationToken cancellationToken = default);
    Task ExtendLeaseAsync(Guid jobId, string workerId, TimeSpan extension, CancellationToken cancellationToken = default);
    Task CompleteJobAsync(Guid jobId, long durationMs, CancellationToken cancellationToken = default);
    Task FailJobAsync(Guid jobId, string errorMessage, CancellationToken cancellationToken = default);
    Task CancelJobAsync(Guid jobId, CancellationToken cancellationToken = default);
    Task<bool> IsCancellationRequestedAsync(Guid jobId, CancellationToken cancellationToken = default);
}
