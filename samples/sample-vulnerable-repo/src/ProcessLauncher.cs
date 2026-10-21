using System.Diagnostics;

namespace VulnerableApp;

public class ProcessLauncher
{
    public void ExecuteUserCommand(string userInput)
    {
        // CWE-78: Potential Command Injection Vulnerability via string concatenation
        Process.Start("cmd.exe", "/c ping " + userInput);
    }
}
