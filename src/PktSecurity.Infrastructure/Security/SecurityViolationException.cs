namespace PktSecurity.Infrastructure.Security;

public class SecurityViolationException : Exception
{
    public string ViolationType { get; }

    public SecurityViolationException(string violationType, string message)
        : base($"Security violation ({violationType}): {message}")
    {
        ViolationType = violationType;
    }

    public SecurityViolationException(string violationType, string message, Exception innerException)
        : base($"Security violation ({violationType}): {message}", innerException)
    {
        ViolationType = violationType;
    }
}
