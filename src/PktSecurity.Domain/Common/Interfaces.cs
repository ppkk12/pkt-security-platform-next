namespace PktSecurity.Domain.Common;

public interface ITenantScoped
{
    Guid TenantId { get; set; }
}

public interface IAuditable
{
    DateTime CreatedAt { get; set; }
}
