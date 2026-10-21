using System.Text.RegularExpressions;

namespace PktSecurity.Infrastructure.Security;

public static class UnifiedDiffPatcher
{
    private static readonly Regex HunkHeaderRegex = new(
        @"^@@\s+-(?<origStart>\d+)(?:,(?<origCount>\d+))?\s+\+(?<newStart>\d+)(?:,(?<newCount>\d+))?\s+@@",
        RegexOptions.Compiled);

    public record PatchResult(
        bool Success,
        string? TargetPath,
        string? PatchedContent,
        string? ErrorMessage);

    public static PatchResult ApplyPatch(string originalContent, string diffText)
    {
        var lines = originalContent.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None).ToList();
        var diffLines = diffText.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);

        string? targetPath = null;
        int diffIdx = 0;

        // 1. Locate --- and +++ lines
        while (diffIdx < diffLines.Length)
        {
            var line = diffLines[diffIdx];
            if (line.StartsWith("+++ "))
            {
                var rawPath = line[4..].Trim();
                if (rawPath.StartsWith("b/")) rawPath = rawPath[2..];
                targetPath = rawPath;
                diffIdx++;
                break;
            }
            diffIdx++;
        }

        if (string.IsNullOrEmpty(targetPath))
        {
            return new PatchResult(false, null, null, "Could not find '+++ ' file header in unified diff");
        }

        // 2. Process hunks
        var patchedLines = new List<string>(lines);
        int lineOffset = 0;

        while (diffIdx < diffLines.Length)
        {
            var line = diffLines[diffIdx];
            if (line.StartsWith("@@"))
            {
                var match = HunkHeaderRegex.Match(line);
                if (!match.Success)
                {
                    diffIdx++;
                    continue;
                }

                int origStart = int.Parse(match.Groups["origStart"].Value);
                // 1-indexed to 0-indexed
                int currentOriginalIndex = (origStart - 1) + lineOffset;
                diffIdx++;

                while (diffIdx < diffLines.Length && !diffLines[diffIdx].StartsWith("@@") && !diffLines[diffIdx].StartsWith("---"))
                {
                    var hLine = diffLines[diffIdx];
                    if (hLine.Length == 0)
                    {
                        currentOriginalIndex++;
                        diffIdx++;
                        continue;
                    }

                    char prefix = hLine[0];
                    string text = hLine[1..];

                    if (prefix == ' ')
                    {
                        // Context line
                        currentOriginalIndex++;
                    }
                    else if (prefix == '-')
                    {
                        // Delete line
                        if (currentOriginalIndex >= 0 && currentOriginalIndex < patchedLines.Count)
                        {
                            patchedLines.RemoveAt(currentOriginalIndex);
                            lineOffset--;
                        }
                    }
                    else if (prefix == '+')
                    {
                        // Insert line
                        if (currentOriginalIndex >= 0 && currentOriginalIndex <= patchedLines.Count)
                        {
                            patchedLines.Insert(currentOriginalIndex, text);
                            currentOriginalIndex++;
                            lineOffset++;
                        }
                        else
                        {
                            patchedLines.Add(text);
                            currentOriginalIndex++;
                            lineOffset++;
                        }
                    }

                    diffIdx++;
                }
            }
            else
            {
                diffIdx++;
            }
        }

        return new PatchResult(true, targetPath, string.Join("\n", patchedLines), null);
    }

    public static async Task<PatchResult> ApplyPatchToWorkspaceAsync(
        string workspaceRoot,
        string diffText,
        CancellationToken cancellationToken = default)
    {
        // First validate diff security
        AiPromptDefense.ValidateDiff(diffText, null);

        var preview = ApplyPatch(string.Empty, diffText);
        if (string.IsNullOrEmpty(preview.TargetPath))
        {
            return preview;
        }

        var normalizedTarget = preview.TargetPath.Replace('/', Path.DirectorySeparatorChar);
        var fullPath = Path.GetFullPath(Path.Combine(workspaceRoot, normalizedTarget));

        if (!fullPath.StartsWith(Path.GetFullPath(workspaceRoot), StringComparison.OrdinalIgnoreCase))
        {
            throw new SecurityViolationException("Patch_PathTraversal", $"Target file '{fullPath}' is outside workspace.");
        }

        if (!File.Exists(fullPath))
        {
            return new PatchResult(false, preview.TargetPath, null, $"Target file '{fullPath}' does not exist.");
        }

        var originalContent = await File.ReadAllTextAsync(fullPath, cancellationToken);
        var result = ApplyPatch(originalContent, diffText);

        if (result.Success && result.PatchedContent != null)
        {
            await File.WriteAllTextAsync(fullPath, result.PatchedContent, cancellationToken);
        }

        return result;
    }
}
