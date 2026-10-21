using PktSecurity.Application.Common.Interfaces;

namespace PktSecurity.Application.Common.Models;

public class TenantContext : ITenantContext
{
    public Guid? CurrentTenantId { get; private set; }

    public void SetTenantId(Guid tenantId)
    {
        CurrentTenantId = tenantId;
    }
}
