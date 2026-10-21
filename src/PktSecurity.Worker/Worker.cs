using PktSecurity.Application.Common.Interfaces;
using PktSecurity.Infrastructure.Services;

namespace PktSecurity.Worker;

public class ScanWorker : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<ScanWorker> _logger;
    private readonly string _workerId = $"worker-{Guid.NewGuid():N}";

    public ScanWorker(IServiceProvider serviceProvider, ILogger<ScanWorker> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("ScanWorker {WorkerId} started.", _workerId);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = _serviceProvider.CreateScope();
                var jobQueue = scope.ServiceProvider.GetRequiredService<IJobQueueProvider>();
                var scanService = scope.ServiceProvider.GetRequiredService<ScanExecutionService>();

                var job = await jobQueue.DequeueJobAsync(_workerId, stoppingToken);
                if (job != null)
                {
                    _logger.LogInformation("Worker {WorkerId} leased job {JobId} for scanner {Scanner}",
                        _workerId, job.Id, job.ScannerName);

                    await scanService.ProcessJobAsync(job, _workerId, stoppingToken);
                }
                else
                {
                    // No job queued; back off briefly
                    await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error in ScanWorker loop");
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            }
        }

        _logger.LogInformation("ScanWorker {WorkerId} stopped.", _workerId);
    }
}
