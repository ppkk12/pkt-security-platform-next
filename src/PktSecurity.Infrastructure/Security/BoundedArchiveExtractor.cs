using System.IO.Compression;

namespace PktSecurity.Infrastructure.Security;

public static class BoundedArchiveExtractor
{
    public const long DefaultMaxSingleFileBytes = 100 * 1024 * 1024; // 100 MB
    public const long DefaultMaxTotalBytes = 500 * 1024 * 1024;      // 500 MB
    public const int DefaultMaxFileCount = 50_000;
    public const double DefaultMaxCompressionRatio = 100.0;
    public const int DefaultMaxDirectoryDepth = 32;

    public static async Task ExtractZipSafelyAsync(
        Stream zipStream,
        string destinationDirectory,
        long maxSingleFileBytes = DefaultMaxSingleFileBytes,
        long maxTotalBytes = DefaultMaxTotalBytes,
        int maxFileCount = DefaultMaxFileCount,
        double maxCompressionRatio = DefaultMaxCompressionRatio,
        int maxDirectoryDepth = DefaultMaxDirectoryDepth,
        CancellationToken cancellationToken = default)
    {
        var fullDestDir = Path.GetFullPath(destinationDirectory);
        if (!fullDestDir.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal))
        {
            fullDestDir += Path.DirectorySeparatorChar;
        }

        Directory.CreateDirectory(fullDestDir);

        using var archive = new ZipArchive(zipStream, ZipArchiveMode.Read, leaveOpen: true);

        long totalExtractedBytes = 0;
        int fileCount = 0;
        var buffer = new byte[81920]; // 80 KB buffer

        foreach (var entry in archive.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();

            fileCount++;
            if (fileCount > maxFileCount)
            {
                throw new SecurityViolationException(
                    "ZipBomb_MaxFilesExceeded",
                    $"Archive exceeds maximum permitted file count of {maxFileCount}.");
            }

            // Path Traversal (Zip Slip) Check
            var rawEntryName = entry.FullName.Replace('/', Path.DirectorySeparatorChar);
            var destinationPath = Path.GetFullPath(Path.Combine(fullDestDir, rawEntryName));

            if (!destinationPath.StartsWith(fullDestDir, StringComparison.OrdinalIgnoreCase))
            {
                throw new SecurityViolationException(
                    "ZipSlip_PathTraversal",
                    $"Entry '{entry.FullName}' targets location outside workspace destination: '{destinationPath}'.");
            }

            // Directory depth check
            var relativePath = Path.GetRelativePath(fullDestDir, destinationPath);
            var depth = relativePath.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries).Length;
            if (depth > maxDirectoryDepth)
            {
                throw new SecurityViolationException(
                    "ZipBomb_DirectoryDepthExceeded",
                    $"Entry '{entry.FullName}' exceeds maximum directory depth of {maxDirectoryDepth}.");
            }

            // Symlink / Reparse Point check
            // On Unix / Zip specifications, bit 0x2000 in ExternalAttributes indicates a symlink
            if ((entry.ExternalAttributes & 0x20000000) != 0 || (entry.ExternalAttributes & 0xA0000000) != 0)
            {
                throw new SecurityViolationException(
                    "Symlink_Denied",
                    $"Symbolic link or reparse point entry '{entry.FullName}' is strictly prohibited.");
            }

            // Check if directory
            if (string.IsNullOrEmpty(entry.Name) || rawEntryName.EndsWith(Path.DirectorySeparatorChar))
            {
                Directory.CreateDirectory(destinationPath);
                continue;
            }

            var parentDir = Path.GetDirectoryName(destinationPath);
            if (!string.IsNullOrEmpty(parentDir))
            {
                Directory.CreateDirectory(parentDir);
            }

            // Stream and extract with continuous byte-level threshold monitoring
            long entryExtractedBytes = 0;
            using (var entryStream = entry.Open())
            using (var fileStream = new FileStream(destinationPath, FileMode.Create, FileAccess.Write, FileShare.None, 4096, useAsync: true))
            {
                int bytesRead;
                while ((bytesRead = await entryStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken)) > 0)
                {
                    entryExtractedBytes += bytesRead;
                    totalExtractedBytes += bytesRead;

                    if (entryExtractedBytes > maxSingleFileBytes)
                    {
                        throw new SecurityViolationException(
                            "ZipBomb_SingleFileLimitExceeded",
                            $"Entry '{entry.FullName}' uncompressed size exceeds limit of {maxSingleFileBytes / (1024 * 1024)} MB.");
                    }

                    if (totalExtractedBytes > maxTotalBytes)
                    {
                        throw new SecurityViolationException(
                            "ZipBomb_TotalSizeLimitExceeded",
                            $"Archive total uncompressed size exceeds limit of {maxTotalBytes / (1024 * 1024)} MB.");
                    }

                    // Check compression ratio if entry has significant uncompressed content
                    if (entry.CompressedLength > 0 && entryExtractedBytes > 10 * 1024 * 1024)
                    {
                        double ratio = (double)entryExtractedBytes / entry.CompressedLength;
                        if (ratio > maxCompressionRatio)
                        {
                            throw new SecurityViolationException(
                                "ZipBomb_CompressionRatioExceeded",
                                $"Entry '{entry.FullName}' compression ratio {ratio:F1}x exceeds maximum allowed {maxCompressionRatio}x.");
                        }
                    }

                    await fileStream.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken);
                }
            }
        }
    }
}
