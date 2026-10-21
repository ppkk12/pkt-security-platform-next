using System.Text.Json;

namespace PktSecurity.Api.Middleware;

public class ProblemDetailsMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ProblemDetailsMiddleware> _logger;

    public ProblemDetailsMiddleware(RequestDelegate next, ILogger<ProblemDetailsMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);

            if (context.Response.StatusCode >= 400 && !context.Response.HasStarted)
            {
                await WriteProblemDetailsResponse(context, context.Response.StatusCode, GetDefaultTitleForStatus(context.Response.StatusCode), null);
            }
        }
        catch (BadHttpRequestException ex)
        {
            _logger.LogWarning(ex, "Bad HTTP request: {Path}", context.Request.Path);
            await WriteProblemDetailsResponse(context, StatusCodes.Status400BadRequest, "Bad Request", ex.Message);
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogWarning(ex, "Unauthorized access: {Path}", context.Request.Path);
            await WriteProblemDetailsResponse(context, StatusCodes.Status403Forbidden, "Forbidden", ex.Message);
        }
        catch (KeyNotFoundException ex)
        {
            _logger.LogWarning(ex, "Resource not found: {Path}", context.Request.Path);
            await WriteProblemDetailsResponse(context, StatusCodes.Status404NotFound, "Not Found", ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unhandled server exception: {Path}", context.Request.Path);
            await WriteProblemDetailsResponse(context, StatusCodes.Status500InternalServerError, "Internal Server Error", "An unexpected error occurred. Please contact system support.");
        }
    }

    private static async Task WriteProblemDetailsResponse(HttpContext context, int statusCode, string title, string? detail)
    {
        if (context.Response.HasStarted) return;

        context.Response.ContentType = "application/problem+json";
        context.Response.StatusCode = statusCode;

        var traceId = context.TraceIdentifier;
        var problemDetails = new
        {
            type = $"https://httpstatuses.io/{statusCode}",
            title,
            status = statusCode,
            detail = detail ?? title,
            instance = context.Request.Path.Value,
            traceId
        };

        var json = JsonSerializer.Serialize(problemDetails, new JsonSerializerOptions { WriteIndented = true });
        await context.Response.WriteAsync(json);
    }

    private static string GetDefaultTitleForStatus(int statusCode) => statusCode switch
    {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "An error occurred"
    };
}
