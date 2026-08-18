using System.Security.Cryptography;
using System.Text.Json;

namespace Target.Windows.Runtime;

public sealed record RuntimeConfigurationArtifact(
    Guid Id,
    string Path,
    string Sha256,
    long Length);

public sealed class RuntimeConfigurationStore
{
    public const int MaximumConfigurationBytes = 10 * 1024 * 1024;
    private readonly string root;

    private RuntimeConfigurationStore(string root)
    {
        this.root = SingBoxEngineLocation.CanonicalPath(root);
    }

    public string Root => root;

    public static RuntimeConfigurationStore Production() =>
        new(SingBoxEngineLocation.GetProductionRuntimeRoot());

    public static RuntimeConfigurationStore ForTesting(string root)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        return new(root);
    }

    public RuntimeConfigurationArtifact Write(Guid id, ReadOnlySpan<byte> content)
    {
        if (id == Guid.Empty || content.Length == 0 || content.Length > MaximumConfigurationBytes)
        {
            throw new RuntimeOperationException(
                RuntimeFailureReason.StorageFailure,
                "The runtime configuration cannot be persisted.");
        }

        RuntimePathSecurity.EnsurePrivateDirectory(root);
        var path = SafePath(id);
        var temporaryPath = SafeTemporaryPath(id);
        try
        {
            using (var stream = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                64 * 1024,
                FileOptions.WriteThrough))
            {
                stream.Write(content);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporaryPath, path, overwrite: true);
            return new RuntimeConfigurationArtifact(
                id,
                path,
                Sha256(content),
                content.Length);
        }
        catch (RuntimeOperationException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new RuntimeOperationException(
                RuntimeFailureReason.StorageFailure,
                "The runtime configuration cannot be persisted.",
                exception);
        }
        finally
        {
            TryDeletePath(temporaryPath);
        }
    }

    public bool ExistsVerified(Guid id, string expectedSha256)
    {
        if (id == Guid.Empty || !RuntimeOwnershipRecord.IsSha256(expectedSha256))
        {
            return false;
        }

        if (!RuntimePathSecurity.IsSafeExistingDirectory(root))
        {
            return false;
        }

        var path = SafePath(id);
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length <= 0 || info.Length > MaximumConfigurationBytes
                || info.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                return false;
            }

            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                64 * 1024,
                FileOptions.SequentialScan);
            return CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(expectedSha256),
                SHA256.HashData(stream));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or FormatException)
        {
            return false;
        }
    }

    public bool Delete(Guid id)
    {
        if (id == Guid.Empty)
        {
            return false;
        }

        if (!Directory.Exists(root))
        {
            return true;
        }

        if (!RuntimePathSecurity.IsSafeExistingDirectory(root))
        {
            return false;
        }

        var path = SafePath(id);
        TryDeletePath(path);
        var deleted = !File.Exists(path);
        TryDeleteEmptyRoot();
        return deleted;
    }

    public void DeleteUnassociatedArtifacts()
    {
        if (!RuntimePathSecurity.IsSafeExistingDirectory(root))
        {
            return;
        }

        foreach (var path in Directory.EnumerateFiles(root, "*", SearchOption.TopDirectoryOnly))
        {
            if (string.Equals(Path.GetFileName(path), RuntimeOwnershipStore.RecordFileName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var canonical = SingBoxEngineLocation.CanonicalPath(path);
            if (IsWithinRoot(canonical))
            {
                TryDeletePath(canonical);
            }
        }

        TryDeleteEmptyRoot();
    }

    private string SafePath(Guid id)
    {
        var path = SingBoxEngineLocation.CanonicalPath(Path.Combine(root, $"{id:D}.json"));
        if (!IsWithinRoot(path))
        {
            throw new RuntimeOperationException(RuntimeFailureReason.StorageFailure, "The runtime path is invalid.");
        }

        return path;
    }

    private string SafeTemporaryPath(Guid id)
    {
        var path = SingBoxEngineLocation.CanonicalPath(Path.Combine(root, $".{id:D}.{Guid.NewGuid():N}.tmp"));
        if (!IsWithinRoot(path))
        {
            throw new RuntimeOperationException(RuntimeFailureReason.StorageFailure, "The runtime path is invalid.");
        }

        return path;
    }

    private bool IsWithinRoot(string path) =>
        path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);

    private void TryDeleteEmptyRoot()
    {
        try
        {
            if (RuntimePathSecurity.IsSafeExistingDirectory(root)
                && !Directory.EnumerateFileSystemEntries(root).Any())
            {
                Directory.Delete(root, recursive: false);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static void TryDeletePath(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    internal static string Sha256(ReadOnlySpan<byte> content) =>
        Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
}

public sealed record RuntimeOwnershipRecord(
    int ProcessId,
    long ProcessCreationTimeFileTimeUtc,
    string ExecutablePath,
    string ExecutableSha256,
    Guid ProfileId,
    long ProfileRevision,
    string SourceConfigurationSha256,
    Guid RuntimeConfigurationId,
    string RuntimeConfigurationSha256,
    string PrimaryHost,
    int PrimaryPort,
    DateTimeOffset RecordedStartTimeUtc)
{
    public bool IsValid(SingBoxEngineLocation location)
    {
        if (ProcessId <= 0 || ProcessCreationTimeFileTimeUtc <= 0
            || ProfileId == Guid.Empty || ProfileRevision <= 0
            || RuntimeConfigurationId == Guid.Empty
            || !IsSha256(ExecutableSha256)
            || !IsSha256(SourceConfigurationSha256)
            || !IsSha256(RuntimeConfigurationSha256)
            || !string.Equals(PrimaryHost, SingBoxEngineConstants.PrimaryHost, StringComparison.Ordinal)
            || PrimaryPort is < 49_152 or > ushort.MaxValue
            || RecordedStartTimeUtc == default
            || string.IsNullOrWhiteSpace(ExecutablePath))
        {
            return false;
        }

        try
        {
            return string.Equals(
                SingBoxEngineLocation.CanonicalPath(ExecutablePath),
                location.ExecutablePath,
                StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    public static bool IsSha256(string? value) =>
        value is { Length: 64 } && value.All(character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');
}

public enum RuntimeOwnershipReadKind
{
    NoRecord,
    ValidRecord,
    MalformedRecord
}

public sealed record RuntimeOwnershipReadResult(
    RuntimeOwnershipReadKind Kind,
    RuntimeOwnershipRecord? Record);

public sealed class RuntimeOwnershipStore
{
    internal const string RecordFileName = "runtime-record.json";
    private const int MaximumRecordBytes = 64 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string root;
    private readonly string recordPath;

    private RuntimeOwnershipStore(string root)
    {
        this.root = SingBoxEngineLocation.CanonicalPath(root);
        recordPath = SingBoxEngineLocation.CanonicalPath(Path.Combine(this.root, RecordFileName));
    }

    public static RuntimeOwnershipStore Production() =>
        new(SingBoxEngineLocation.GetProductionRuntimeRoot());

    public static RuntimeOwnershipStore ForTesting(string root)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        return new(root);
    }

    public RuntimeOwnershipReadResult Read()
    {
        try
        {
            if (Directory.Exists(root) && !RuntimePathSecurity.IsSafeExistingDirectory(root))
            {
                return new(RuntimeOwnershipReadKind.MalformedRecord, null);
            }

            var info = new FileInfo(recordPath);
            if (!info.Exists)
            {
                return new(RuntimeOwnershipReadKind.NoRecord, null);
            }

            if (info.Length <= 0 || info.Length > MaximumRecordBytes
                || info.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                return new(RuntimeOwnershipReadKind.MalformedRecord, null);
            }

            var content = File.ReadAllBytes(recordPath);
            var record = JsonSerializer.Deserialize<RuntimeOwnershipRecord>(content, JsonOptions);
            return record is null
                ? new(RuntimeOwnershipReadKind.MalformedRecord, null)
                : new(RuntimeOwnershipReadKind.ValidRecord, record);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return new(RuntimeOwnershipReadKind.MalformedRecord, null);
        }
    }

    public void Save(RuntimeOwnershipRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        RuntimePathSecurity.EnsurePrivateDirectory(root);
        var content = JsonSerializer.SerializeToUtf8Bytes(record, JsonOptions);
        if (content.Length > MaximumRecordBytes)
        {
            throw new RuntimeOperationException(RuntimeFailureReason.StorageFailure, "The runtime record is invalid.");
        }

        var temporaryPath = SingBoxEngineLocation.CanonicalPath(
            Path.Combine(root, $".{RecordFileName}.{Guid.NewGuid():N}.tmp"));
        try
        {
            using (var stream = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.WriteThrough))
            {
                stream.Write(content);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporaryPath, recordPath, overwrite: true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new RuntimeOperationException(
                RuntimeFailureReason.StorageFailure,
                "The runtime ownership record could not be persisted.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(content);
            try
            {
                File.Delete(temporaryPath);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    public bool ClearIfMatches(RuntimeOwnershipRecord expected)
    {
        var current = Read();
        if (current.Kind != RuntimeOwnershipReadKind.ValidRecord
            || current.Record != expected)
        {
            return false;
        }

        try
        {
            File.Delete(recordPath);
            TryDeleteEmptyRoot();
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private void TryDeleteEmptyRoot()
    {
        try
        {
            if (RuntimePathSecurity.IsSafeExistingDirectory(root)
                && !Directory.EnumerateFileSystemEntries(root).Any())
            {
                Directory.Delete(root, recursive: false);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}

internal static class RuntimePathSecurity
{
    public static void EnsurePrivateDirectory(string path)
    {
        Directory.CreateDirectory(path);
        if (!IsSafeExistingDirectory(path))
        {
            throw new RuntimeOperationException(
                RuntimeFailureReason.StorageFailure,
                "The runtime directory is not a regular per-user directory.");
        }
    }

    public static bool IsSafeExistingDirectory(string path)
    {
        try
        {
            var info = new DirectoryInfo(path);
            return info.Exists && !info.Attributes.HasFlag(FileAttributes.ReparsePoint);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }
}
