using System.Data;
using Dapper;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using PktSecurity.Application.Common.Interfaces;
using PktSecurity.Domain.Entities;
using PktSecurity.Domain.Enums;
using PktSecurity.Infrastructure.Data;

namespace PktSecurity.Infrastructure.Jobs;

public class PostgresJobQueueProvider : IJobQueueProvider
{
    static PostgresJobQueueProvider()
    {
        Dapper.DefaultTypeMap.MatchNamesWithUnderscores = true;
    }

    private readonly string _connectionString;

    public PostgresJobQueueProvider(string connectionString)
    {
        _connectionString = connectionString;
    }

    private async Task<NpgsqlConnection> CreateConnectionAsync(CancellationToken cancellationToken)
    {
        var conn = new NpgsqlConnection(_connectionString);
        await conn.OpenAsync(cancellationToken);
        return conn;
    }

    public async Task<ScanJob?> DequeueJobAsync(string workerId, CancellationToken cancellationToken = default)
    {
        await using var conn = await CreateConnectionAsync(cancellationToken);

        // Clear any tenant setting so worker can lease any scheduled job
        await conn.ExecuteAsync("SELECT set_config('app.current_tenant_id', '', false);");

        // DeadLetter Reaper: transition any scan_jobs whose lease expired and reached max_attempts to Failed,
        // and also mark the associated running scans as Failed so scans don't remain stuck in Running.
        const string deadLetterSql = @"
            WITH dead_jobs AS (
                UPDATE scan_jobs
                SET status = @failedStatus,
                    error_message = 'Job lease expired and exceeded maximum retry attempts (DeadLetter).',
                    completed_at = NOW()
                WHERE status = @runningStatus
                  AND leased_until < NOW()
                  AND attempt_count >= max_attempts
                RETURNING scan_id
            )
            UPDATE scans
            SET status = @scanFailedStatus,
                error_message = 'Scan failed due to worker failure and retry exhaustion (DeadLetter).',
                completed_at = NOW()
            WHERE id IN (SELECT scan_id FROM dead_jobs)
              AND status = @scanRunningStatus;
        ";

        await conn.ExecuteAsync(new CommandDefinition(
            deadLetterSql,
            new
            {
                runningStatus = (int)ScanJobStatus.Running,
                failedStatus = (int)ScanJobStatus.Failed,
                scanRunningStatus = (int)ScanStatus.Running,
                scanFailedStatus = (int)ScanStatus.Failed
            },
            cancellationToken: cancellationToken));

        const string sql = @"
            UPDATE scan_jobs
            SET status = @runningStatus,
                lease_owner = @workerId,
                leased_until = NOW() + INTERVAL '2 minutes',
                heartbeat_at = NOW(),
                attempt_count = attempt_count + 1,
                started_at = COALESCE(started_at, NOW())
            WHERE id = (
                SELECT id FROM scan_jobs
                WHERE status = @queuedStatus
                   OR (status = @runningStatus AND leased_until < NOW() AND attempt_count < max_attempts)
                ORDER BY priority DESC, created_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            RETURNING 
                id AS Id,
                tenant_id AS TenantId,
                scan_id AS ScanId,
                scanner_name AS ScannerName,
                status AS Status,
                priority AS Priority,
                lease_owner AS LeaseOwner,
                leased_until AS LeasedUntil,
                heartbeat_at AS HeartbeatAt,
                attempt_count AS AttemptCount,
                max_attempts AS MaxAttempts,
                cancel_requested AS CancelRequested,
                execution_duration_ms AS ExecutionDurationMs,
                error_message AS ErrorMessage,
                created_at AS CreatedAt,
                started_at AS StartedAt,
                completed_at AS CompletedAt;
        ";

        var job = await conn.QueryFirstOrDefaultAsync<ScanJob>(new CommandDefinition(
            sql,
            new
            {
                workerId,
                queuedStatus = (int)ScanJobStatus.Queued,
                runningStatus = (int)ScanJobStatus.Running
            },
            cancellationToken: cancellationToken));

        return job;
    }

    public async Task ExtendLeaseAsync(Guid jobId, string workerId, TimeSpan extension, CancellationToken cancellationToken = default)
    {
        await using var conn = await CreateConnectionAsync(cancellationToken);
        await conn.ExecuteAsync("SELECT set_config('app.current_tenant_id', '', false);");

        const string sql = @"
            UPDATE scan_jobs
            SET leased_until = NOW() + (@seconds || ' seconds')::interval,
                heartbeat_at = NOW()
            WHERE id = @jobId AND lease_owner = @workerId;
        ";

        await conn.ExecuteAsync(new CommandDefinition(
            sql,
            new { jobId, workerId, seconds = (int)extension.TotalSeconds },
            cancellationToken: cancellationToken));
    }

    public async Task CompleteJobAsync(Guid jobId, long durationMs, CancellationToken cancellationToken = default)
    {
        await using var conn = await CreateConnectionAsync(cancellationToken);
        await conn.ExecuteAsync("SELECT set_config('app.current_tenant_id', '', false);");

        const string sql = @"
            UPDATE scan_jobs
            SET status = @completedStatus,
                execution_duration_ms = @durationMs,
                completed_at = NOW()
            WHERE id = @jobId;
        ";

        await conn.ExecuteAsync(new CommandDefinition(
            sql,
            new { jobId, durationMs, completedStatus = (int)ScanJobStatus.Completed },
            cancellationToken: cancellationToken));
    }

    public async Task FailJobAsync(Guid jobId, string errorMessage, CancellationToken cancellationToken = default)
    {
        await using var conn = await CreateConnectionAsync(cancellationToken);
        await conn.ExecuteAsync("SELECT set_config('app.current_tenant_id', '', false);");

        const string sql = @"
            UPDATE scan_jobs
            SET status = @failedStatus,
                error_message = @errorMessage,
                completed_at = NOW()
            WHERE id = @jobId;
        ";

        await conn.ExecuteAsync(new CommandDefinition(
            sql,
            new { jobId, errorMessage, failedStatus = (int)ScanJobStatus.Failed },
            cancellationToken: cancellationToken));
    }

    public async Task CancelJobAsync(Guid jobId, CancellationToken cancellationToken = default)
    {
        await using var conn = await CreateConnectionAsync(cancellationToken);
        await conn.ExecuteAsync("SELECT set_config('app.current_tenant_id', '', false);");

        const string sql = @"
            UPDATE scan_jobs
            SET cancel_requested = true,
                status = @cancelledStatus,
                completed_at = NOW()
            WHERE id = @jobId;
        ";

        await conn.ExecuteAsync(new CommandDefinition(
            sql,
            new { jobId, cancelledStatus = (int)ScanJobStatus.Cancelled },
            cancellationToken: cancellationToken));
    }

    public async Task<bool> IsCancellationRequestedAsync(Guid jobId, CancellationToken cancellationToken = default)
    {
        await using var conn = await CreateConnectionAsync(cancellationToken);
        await conn.ExecuteAsync("SELECT set_config('app.current_tenant_id', '', false);");

        const string sql = "SELECT cancel_requested FROM scan_jobs WHERE id = @jobId;";
        return await conn.ExecuteScalarAsync<bool>(new CommandDefinition(sql, new { jobId }, cancellationToken: cancellationToken));
    }
}
