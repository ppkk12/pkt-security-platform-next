using System.Data.SqlClient;

namespace VulnerableApp;

public class DatabaseService
{
    private readonly string _connectionString = "Server=localhost;Database=TestDb;";

    public void GetUserByUsername(string username)
    {
        // CWE-89: Potential SQL Injection Vulnerability via string concatenation
        var query = "SELECT * FROM Users WHERE Username = '" + username + "'";

        using var connection = new SqlConnection(_connectionString);
        using var command = new SqlCommand(query, connection);
        connection.Open();
        using var reader = command.ExecuteReader();
    }
}
