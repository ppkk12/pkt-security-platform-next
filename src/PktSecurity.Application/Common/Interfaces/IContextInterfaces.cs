using PktSecurity.Domain.Enums;

namespace PktSecurity.Application.Common.Interfaces;

public interface ITenantContext
{
    Guid? CurrentTenantId { get; }
    void SetTenantId(Guid tenantId);
}

public interface ICurrentUserContext
{
    Guid? UserId { get; }
    UserRole? Role { get; }
    string? Email { get; }
    bool IsAuthenticated { get; }
}
