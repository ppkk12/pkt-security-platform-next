using System.Data.Common;
using Microsoft.EntityFrameworkCore.Diagnostics;
using PktSecurity.Application.Common.Interfaces;

namespace PktSecurity.Infrastructure.Data;

public class TenantSecurityInterceptor : DbCommandInterceptor
{
    private readonly ITenantContext _tenantContext;

    public TenantSecurityInterceptor(ITenantContext tenantContext)
    {
        _tenantContext = tenantContext;
    }

    public override InterceptionResult<DbDataReader> ReaderExecuting(
        DbCommand command,
        CommandEventData eventData,
        InterceptionResult<DbDataReader> result)
    {
        ApplyTenantSession(command);
        return base.ReaderExecuting(command, eventData, result);
    }

    public override async ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
        DbCommand command,
        CommandEventData eventData,
        InterceptionResult<DbDataReader> result,
        CancellationToken cancellationToken = default)
    {
        await ApplyTenantSessionAsync(command, cancellationToken);
        return await base.ReaderExecutingAsync(command, eventData, result, cancellationToken);
    }

    public override InterceptionResult<int> NonQueryExecuting(
        DbCommand command,
        CommandEventData eventData,
        InterceptionResult<int> result)
    {
        ApplyTenantSession(command);
        return base.NonQueryExecuting(command, eventData, result);
    }

    public override async ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
        DbCommand command,
        CommandEventData eventData,
        InterceptionResult<int> result,
        CancellationToken cancellationToken = default)
    {
        await ApplyTenantSessionAsync(command, cancellationToken);
        return await base.NonQueryExecutingAsync(command, eventData, result, cancellationToken);
    }

    public override InterceptionResult<object> ScalarExecuting(
        DbCommand command,
        CommandEventData eventData,
        InterceptionResult<object> result)
    {
        ApplyTenantSession(command);
        return base.ScalarExecuting(command, eventData, result);
    }

    public override async ValueTask<InterceptionResult<object>> ScalarExecutingAsync(
        DbCommand command,
        CommandEventData eventData,
        InterceptionResult<object> result,
        CancellationToken cancellationToken = default)
    {
        await ApplyTenantSessionAsync(command, cancellationToken);
        return await base.ScalarExecutingAsync(command, eventData, result, cancellationToken);
    }

    private void ApplyTenantSession(DbCommand command)
    {
        if (command.Connection == null || command.Connection.State != System.Data.ConnectionState.Open)
            return;

        if (command.CommandText.Contains("set_config('app.current_tenant_id'"))
            return;

        var tenantId = _tenantContext.CurrentTenantId;
        var val = tenantId.HasValue ? tenantId.Value.ToString() : string.Empty;

        using var setCmd = command.Connection.CreateCommand();
        if (command.Transaction != null)
            setCmd.Transaction = command.Transaction;

        var param = setCmd.CreateParameter();
        param.ParameterName = "tenantVal";
        param.Value = val;
        setCmd.Parameters.Add(param);

        setCmd.CommandText = "SELECT set_config('app.current_tenant_id', @tenantVal, false);";
        setCmd.ExecuteNonQuery();
    }

    private async Task ApplyTenantSessionAsync(DbCommand command, CancellationToken cancellationToken)
    {
        if (command.Connection == null || command.Connection.State != System.Data.ConnectionState.Open)
            return;

        if (command.CommandText.Contains("set_config('app.current_tenant_id'"))
            return;

        var tenantId = _tenantContext.CurrentTenantId;
        var val = tenantId.HasValue ? tenantId.Value.ToString() : string.Empty;

        await using var setCmd = command.Connection.CreateCommand();
        if (command.Transaction != null)
            setCmd.Transaction = command.Transaction;

        var param = setCmd.CreateParameter();
        param.ParameterName = "tenantVal";
        param.Value = val;
        setCmd.Parameters.Add(param);

        setCmd.CommandText = "SELECT set_config('app.current_tenant_id', @tenantVal, false);";
        await setCmd.ExecuteNonQueryAsync(cancellationToken);
    }
}
