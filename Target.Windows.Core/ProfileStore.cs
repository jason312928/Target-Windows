using System.Security.Cryptography;
using System.Text.Json;

namespace Target.Windows.Core;

public sealed class ProfileStore : IDisposable
{
    private const string StorageMagic = "Target.Windows.ProfileStorage";
    private const int StorageVersion = 1;
    private const string MarkerFileName = "storage-format.json";
    private const string ManifestFileName = "profiles.json";
    private const string SelectionFileName = "selected-profile.json";
    private const string CurrentConfigurationFileName = "config.json";
    private const string VersionsDirectoryName = "versions";
    private const string ManifestKind = "manifest";
    private const string SelectionKind = "selection";
    private const string CurrentConfigurationKind = "currentConfiguration";
    private const string RevisionKind = "revision";

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly object gate = new();
    private readonly string root;
    private readonly IProfileFileWriter fileWriter;
    private readonly TimeProvider timeProvider;
    private readonly byte[] key;
    private List<Profile> profiles;
    private Guid? selectedProfileId;
    private bool disposed;

    private ProfileStore(
        string root,
        byte[] key,
        IProfileFileWriter fileWriter,
        TimeProvider timeProvider,
        List<Profile> profiles,
        Guid? selectedProfileId)
    {
        this.root = root;
        this.key = key;
        this.fileWriter = fileWriter;
        this.timeProvider = timeProvider;
        this.profiles = profiles;
        this.selectedProfileId = selectedProfileId;
    }

    public Guid? SelectedProfileId
    {
        get
        {
            lock (gate)
            {
                ThrowIfDisposed();
                return selectedProfileId;
            }
        }
    }

    public static ProfileStore Open(
        string root,
        IProfileEncryptionKeyProvider keyProvider,
        IProfileFileWriter? fileWriter = null,
        TimeProvider? timeProvider = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        ArgumentNullException.ThrowIfNull(keyProvider);

        var fullRoot = Path.GetFullPath(root);
        var writer = fileWriter ?? new DurableProfileFileWriter();
        var clock = timeProvider ?? TimeProvider.System;
        var isNewStore = IsNewStore(fullRoot);

        if (!isNewStore)
        {
            ValidateMarker(fullRoot);
        }

        var key = keyProvider.GetKey(
            isNewStore ? ProfileKeyAccess.InitializeNewStore : ProfileKeyAccess.OpenExistingStore);
        if (key.Length != 32)
        {
            CryptographicOperations.ZeroMemory(key);
            throw new ProfileStorageException(
                ProfileStorageError.ProtectedKeyInvalid,
                "The profile encryption key is invalid.");
        }

        try
        {
            if (isNewStore)
            {
                return InitializeNewStore(fullRoot, key, writer, clock);
            }

            return OpenExistingStore(fullRoot, key, writer, clock);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(key);
            throw;
        }
    }

    public static ProfileStore OpenDefault()
    {
        var keyProvider = new DpapiProfileEncryptionKeyProvider(ProfileStoragePaths.GetDefaultProtectedKeyPath());
        return Open(ProfileStoragePaths.GetDefaultProfileRoot(), keyProvider);
    }

    public IReadOnlyList<Profile> ListProfiles()
    {
        lock (gate)
        {
            ThrowIfDisposed();
            return profiles.ToArray();
        }
    }

    public Profile CreateProfile(string name, ReadOnlySpan<byte> initialConfiguration)
    {
        var normalizedName = ValidateAndNormalizeName(name);
        lock (gate)
        {
            ThrowIfDisposed();
            var now = timeProvider.GetUtcNow();
            var profile = new Profile(Guid.NewGuid(), normalizedName, now, now, 1);
            var updatedProfiles = new List<Profile>(profiles) { profile };
            var shouldSelect = selectedProfileId is null;

            var revisionPath = GetRevisionPath(profile.Id, 1);
            var currentPath = GetCurrentConfigurationPath(profile.Id);
            var manifestBytes = EncryptJson(new ManifestRecord(updatedProfiles), ManifestKind, ManifestLogicalPath());
            var revisionBytes = EncryptedRecordCodec.Encrypt(
                initialConfiguration,
                key,
                RevisionKind,
                RevisionLogicalPath(profile.Id, 1));
            var currentBytes = EncryptedRecordCodec.Encrypt(
                initialConfiguration,
                key,
                CurrentConfigurationKind,
                CurrentConfigurationLogicalPath(profile.Id));
            byte[]? previousSelectionBytes = null;
            byte[]? selectionBytes = null;

            if (shouldSelect)
            {
                previousSelectionBytes = ReadFile(SelectionPath(), ProfileStorageError.InvalidStoredMetadata);
                selectionBytes = EncryptJson(
                    new SelectionRecord(profile.Id),
                    SelectionKind,
                    SelectionLogicalPath());
            }

            try
            {
                fileWriter.WriteAtomically(revisionPath, revisionBytes);
                fileWriter.WriteAtomically(currentPath, currentBytes);
                if (selectionBytes is not null)
                {
                    fileWriter.WriteAtomically(SelectionPath(), selectionBytes);
                }

                fileWriter.WriteAtomically(ManifestPath(), manifestBytes);
            }
            catch (Exception exception)
            {
                if (previousSelectionBytes is not null)
                {
                    TryRestoreRecord(SelectionPath(), previousSelectionBytes);
                }

                TryDeleteNewProfileDirectory(profile.Id);
                throw AsPersistenceFailure(exception);
            }
            finally
            {
                Zero(manifestBytes, revisionBytes, currentBytes, previousSelectionBytes, selectionBytes);
            }

            profiles = updatedProfiles;
            if (shouldSelect)
            {
                selectedProfileId = profile.Id;
            }

            return profile;
        }
    }

    public void SelectProfile(Guid profileId)
    {
        lock (gate)
        {
            ThrowIfDisposed();
            EnsureProfileExists(profileId);
            var selectionBytes = EncryptJson(
                new SelectionRecord(profileId),
                SelectionKind,
                SelectionLogicalPath());
            try
            {
                fileWriter.WriteAtomically(SelectionPath(), selectionBytes);
                selectedProfileId = profileId;
            }
            catch (Exception exception)
            {
                throw AsPersistenceFailure(exception);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(selectionBytes);
            }
        }
    }

    public ProfileConfiguration ReadCurrentConfiguration(Guid profileId)
    {
        lock (gate)
        {
            ThrowIfDisposed();
            var profile = EnsureProfileExists(profileId);
            var envelope = ReadFile(GetCurrentConfigurationPath(profileId), ProfileStorageError.InvalidStoredMetadata);
            try
            {
                var content = EncryptedRecordCodec.Decrypt(
                    envelope,
                    key,
                    CurrentConfigurationKind,
                    CurrentConfigurationLogicalPath(profileId));
                return new ProfileConfiguration(profile.CurrentRevision, content);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(envelope);
            }
        }
    }

    public Profile PersistConfiguration(Guid profileId, ReadOnlySpan<byte> configuration)
    {
        lock (gate)
        {
            ThrowIfDisposed();
            var profileIndex = profiles.FindIndex(profile => profile.Id == profileId);
            if (profileIndex < 0)
            {
                throw ProfileNotFound();
            }

            var existingProfile = profiles[profileIndex];
            long nextRevision;
            try
            {
                nextRevision = checked(existingProfile.CurrentRevision + 1);
            }
            catch (OverflowException exception)
            {
                throw new ProfileStorageException(
                    ProfileStorageError.InvalidStoredMetadata,
                    "The profile revision metadata is invalid.",
                    exception);
            }

            var updatedProfile = existingProfile with
            {
                UpdatedAt = timeProvider.GetUtcNow(),
                CurrentRevision = nextRevision
            };
            var updatedProfiles = new List<Profile>(profiles);
            updatedProfiles[profileIndex] = updatedProfile;

            var currentPath = GetCurrentConfigurationPath(profileId);
            var revisionPath = GetRevisionPath(profileId, nextRevision);
            var previousCurrentBytes = ReadFile(currentPath, ProfileStorageError.InvalidStoredMetadata);
            var revisionBytes = EncryptedRecordCodec.Encrypt(
                configuration,
                key,
                RevisionKind,
                RevisionLogicalPath(profileId, nextRevision));
            var currentBytes = EncryptedRecordCodec.Encrypt(
                configuration,
                key,
                CurrentConfigurationKind,
                CurrentConfigurationLogicalPath(profileId));
            var manifestBytes = EncryptJson(new ManifestRecord(updatedProfiles), ManifestKind, ManifestLogicalPath());
            var currentWasWritten = false;

            try
            {
                fileWriter.WriteAtomically(revisionPath, revisionBytes);
                fileWriter.WriteAtomically(currentPath, currentBytes);
                currentWasWritten = true;
                fileWriter.WriteAtomically(ManifestPath(), manifestBytes);
            }
            catch (Exception exception)
            {
                if (currentWasWritten)
                {
                    TryRestoreRecord(currentPath, previousCurrentBytes);
                }

                TryDeleteFile(revisionPath);
                throw AsPersistenceFailure(exception);
            }
            finally
            {
                Zero(previousCurrentBytes, revisionBytes, currentBytes, manifestBytes);
            }

            profiles = updatedProfiles;
            return updatedProfile;
        }
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (disposed)
            {
                return;
            }

            CryptographicOperations.ZeroMemory(key);
            disposed = true;
        }
    }

    private static ProfileStore InitializeNewStore(
        string root,
        byte[] key,
        IProfileFileWriter writer,
        TimeProvider clock)
    {
        Directory.CreateDirectory(root);
        var profiles = new List<Profile>();
        var manifestBytes = EncryptJsonStatic(
            new ManifestRecord(profiles),
            key,
            ManifestKind,
            ManifestLogicalPath());
        var selectionBytes = EncryptJsonStatic(
            new SelectionRecord(null),
            key,
            SelectionKind,
            SelectionLogicalPath());
        var markerBytes = JsonSerializer.SerializeToUtf8Bytes(
            new StorageMarker(StorageMagic, StorageVersion),
            JsonOptions);

        try
        {
            writer.WriteAtomically(Path.Combine(root, ManifestFileName), manifestBytes);
            writer.WriteAtomically(Path.Combine(root, SelectionFileName), selectionBytes);
            writer.WriteAtomically(Path.Combine(root, MarkerFileName), markerBytes);
            return new ProfileStore(root, key, writer, clock, profiles, null);
        }
        catch (Exception exception)
        {
            throw AsPersistenceFailure(exception);
        }
        finally
        {
            Zero(manifestBytes, selectionBytes, markerBytes);
        }
    }

    private static ProfileStore OpenExistingStore(
        string root,
        byte[] key,
        IProfileFileWriter writer,
        TimeProvider clock)
    {
        var manifestEnvelope = ReadFileStatic(
            Path.Combine(root, ManifestFileName),
            ProfileStorageError.InvalidStoredMetadata);
        var selectionEnvelope = ReadFileStatic(
            Path.Combine(root, SelectionFileName),
            ProfileStorageError.InvalidStoredMetadata);
        try
        {
            var manifest = DecryptJson<ManifestRecord>(
                manifestEnvelope,
                key,
                ManifestKind,
                ManifestLogicalPath());
            var selection = DecryptJson<SelectionRecord>(
                selectionEnvelope,
                key,
                SelectionKind,
                SelectionLogicalPath());
            var profiles = ValidateManifest(manifest);
            ValidateSelection(selection.SelectedProfileId, profiles);
            ValidateTree(root, key, profiles);
            return new ProfileStore(root, key, writer, clock, profiles, selection.SelectedProfileId);
        }
        finally
        {
            Zero(manifestEnvelope, selectionEnvelope);
        }
    }

    private static void ValidateMarker(string root)
    {
        var markerPath = Path.Combine(root, MarkerFileName);
        if (!File.Exists(markerPath))
        {
            throw new ProfileStorageException(
                ProfileStorageError.MixedOrDowngradedStorage,
                "The profile store does not contain the encrypted storage marker.");
        }

        StorageMarker? marker;
        try
        {
            marker = JsonSerializer.Deserialize<StorageMarker>(File.ReadAllBytes(markerPath), JsonOptions);
        }
        catch (JsonException exception)
        {
            throw new ProfileStorageException(
                ProfileStorageError.MixedOrDowngradedStorage,
                "The profile store marker is invalid.",
                exception);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new ProfileStorageException(
                ProfileStorageError.PersistenceFailure,
                "The profile store marker could not be read.",
                exception);
        }

        if (marker is null || !string.Equals(marker.Magic, StorageMagic, StringComparison.Ordinal))
        {
            throw new ProfileStorageException(
                ProfileStorageError.MixedOrDowngradedStorage,
                "The profile store marker is invalid.");
        }

        if (marker.Version != StorageVersion)
        {
            throw new ProfileStorageException(
                ProfileStorageError.UnsupportedStorageVersion,
                "The profile storage version is unsupported.");
        }
    }

    private static List<Profile> ValidateManifest(ManifestRecord manifest)
    {
        if (manifest.Profiles is null)
        {
            throw InvalidMetadata();
        }

        var ids = new HashSet<Guid>();
        foreach (var profile in manifest.Profiles)
        {
            if (profile.Id == Guid.Empty ||
                !ids.Add(profile.Id) ||
                string.IsNullOrWhiteSpace(profile.Name) ||
                profile.Name != profile.Name.Trim() ||
                profile.CurrentRevision < 1 ||
                profile.UpdatedAt < profile.CreatedAt)
            {
                throw InvalidMetadata();
            }
        }

        return manifest.Profiles.ToList();
    }

    private static void ValidateSelection(Guid? selectedProfileId, IReadOnlyCollection<Profile> profiles)
    {
        if (selectedProfileId is not null && profiles.All(profile => profile.Id != selectedProfileId.Value))
        {
            throw InvalidMetadata();
        }
    }

    private static void ValidateTree(string root, byte[] key, IReadOnlyCollection<Profile> profiles)
    {
        var expectedRootFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            MarkerFileName,
            ManifestFileName,
            SelectionFileName
        };
        foreach (var file in Directory.EnumerateFiles(root))
        {
            if (!expectedRootFiles.Contains(Path.GetFileName(file)))
            {
                throw MixedStorage();
            }
        }

        var expectedDirectories = profiles
            .Select(profile => profile.Id.ToString("D"))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var directory in Directory.EnumerateDirectories(root))
        {
            if (!expectedDirectories.Contains(Path.GetFileName(directory)))
            {
                throw MixedStorage();
            }
        }

        foreach (var profile in profiles)
        {
            ValidateProfileTree(root, key, profile);
        }
    }

    private static void ValidateProfileTree(string root, byte[] key, Profile profile)
    {
        var profileDirectory = Path.Combine(root, profile.Id.ToString("D"));
        var versionsDirectory = Path.Combine(profileDirectory, VersionsDirectoryName);
        if (!Directory.Exists(profileDirectory) || !Directory.Exists(versionsDirectory))
        {
            throw InvalidMetadata();
        }

        var profileFiles = Directory.EnumerateFiles(profileDirectory).Select(Path.GetFileName).ToArray();
        if (profileFiles.Length != 1 ||
            !string.Equals(profileFiles[0], CurrentConfigurationFileName, StringComparison.OrdinalIgnoreCase) ||
            Directory.EnumerateDirectories(profileDirectory).Any(directory =>
                !string.Equals(Path.GetFileName(directory), VersionsDirectoryName, StringComparison.OrdinalIgnoreCase)))
        {
            throw MixedStorage();
        }

        var versionFiles = Directory.EnumerateFiles(versionsDirectory).ToArray();
        if (versionFiles.Length != profile.CurrentRevision || Directory.EnumerateDirectories(versionsDirectory).Any())
        {
            throw InvalidMetadata();
        }

        byte[]? current = null;
        byte[]? currentRevision = null;
        try
        {
            var currentEnvelope = ReadFileStatic(
                Path.Combine(profileDirectory, CurrentConfigurationFileName),
                ProfileStorageError.InvalidStoredMetadata);
            try
            {
                current = EncryptedRecordCodec.Decrypt(
                    currentEnvelope,
                    key,
                    CurrentConfigurationKind,
                    CurrentConfigurationLogicalPath(profile.Id));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(currentEnvelope);
            }

            for (long revision = 1; revision <= profile.CurrentRevision; revision++)
            {
                var revisionPath = Path.Combine(versionsDirectory, $"{revision}.json");
                var revisionEnvelope = ReadFileStatic(revisionPath, ProfileStorageError.InvalidStoredMetadata);
                try
                {
                    var content = EncryptedRecordCodec.Decrypt(
                        revisionEnvelope,
                        key,
                        RevisionKind,
                        RevisionLogicalPath(profile.Id, revision));
                    if (revision == profile.CurrentRevision)
                    {
                        currentRevision = content;
                    }
                    else
                    {
                        CryptographicOperations.ZeroMemory(content);
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(revisionEnvelope);
                }
            }

            if (currentRevision is null || !current.AsSpan().SequenceEqual(currentRevision))
            {
                throw InvalidMetadata();
            }
        }
        finally
        {
            Zero(current, currentRevision);
        }
    }

    private static bool IsNewStore(string root) =>
        !Directory.Exists(root) || !Directory.EnumerateFileSystemEntries(root).Any();

    private static string ValidateAndNormalizeName(string name)
    {
        if (name is null || string.IsNullOrWhiteSpace(name))
        {
            throw new ProfileStorageException(
                ProfileStorageError.InvalidProfileName,
                "The profile name must not be empty.");
        }

        return name.Trim();
    }

    private Profile EnsureProfileExists(Guid profileId)
    {
        var profile = profiles.FirstOrDefault(profile => profile.Id == profileId);
        return profile ?? throw ProfileNotFound();
    }

    private byte[] EncryptJson<T>(T value, string kind, string logicalPath) =>
        EncryptJsonStatic(value, key, kind, logicalPath);

    private static byte[] EncryptJsonStatic<T>(T value, byte[] key, string kind, string logicalPath)
    {
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);
        try
        {
            return EncryptedRecordCodec.Encrypt(plaintext, key, kind, logicalPath);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static T DecryptJson<T>(byte[] envelope, byte[] key, string kind, string logicalPath)
    {
        var plaintext = EncryptedRecordCodec.Decrypt(envelope, key, kind, logicalPath);
        try
        {
            return JsonSerializer.Deserialize<T>(plaintext, JsonOptions) ?? throw InvalidMetadata();
        }
        catch (JsonException exception)
        {
            throw new ProfileStorageException(
                ProfileStorageError.InvalidStoredMetadata,
                "Authenticated profile metadata is invalid.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private string ManifestPath() => Path.Combine(root, ManifestFileName);
    private string SelectionPath() => Path.Combine(root, SelectionFileName);
    private string GetCurrentConfigurationPath(Guid profileId) =>
        Path.Combine(root, profileId.ToString("D"), CurrentConfigurationFileName);
    private string GetRevisionPath(Guid profileId, long revision) =>
        Path.Combine(root, profileId.ToString("D"), VersionsDirectoryName, $"{revision}.json");

    private static string ManifestLogicalPath() => ManifestFileName;
    private static string SelectionLogicalPath() => SelectionFileName;
    private static string CurrentConfigurationLogicalPath(Guid profileId) =>
        $"{profileId:D}/{CurrentConfigurationFileName}";
    private static string RevisionLogicalPath(Guid profileId, long revision) =>
        $"{profileId:D}/{VersionsDirectoryName}/{revision}.json";

    private byte[] ReadFile(string path, ProfileStorageError missingError) => ReadFileStatic(path, missingError);

    private static byte[] ReadFileStatic(string path, ProfileStorageError missingError)
    {
        try
        {
            return File.ReadAllBytes(path);
        }
        catch (FileNotFoundException exception)
        {
            throw new ProfileStorageException(missingError, "A required profile storage record is missing.", exception);
        }
        catch (DirectoryNotFoundException exception)
        {
            throw new ProfileStorageException(missingError, "A required profile storage record is missing.", exception);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new ProfileStorageException(
                ProfileStorageError.PersistenceFailure,
                "A profile storage record could not be read.",
                exception);
        }
    }

    private void TryRestoreRecord(string path, byte[] content)
    {
        try
        {
            fileWriter.WriteAtomically(path, content);
        }
        catch (Exception exception)
        {
            throw new ProfileStorageException(
                ProfileStorageError.PersistenceFailure,
                "The previous encrypted profile record could not be restored.",
                exception);
        }
    }

    private void TryDeleteNewProfileDirectory(Guid profileId)
    {
        var directory = Path.Combine(root, profileId.ToString("D"));
        try
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new ProfileStorageException(
                ProfileStorageError.PersistenceFailure,
                "Incomplete encrypted profile records could not be cleaned up.",
                exception);
        }
    }

    private static void TryDeleteFile(string path)
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

    private static ProfileStorageException AsPersistenceFailure(Exception exception) =>
        exception as ProfileStorageException ?? new ProfileStorageException(
            ProfileStorageError.PersistenceFailure,
            "The encrypted profile store update failed.",
            exception);

    private static ProfileStorageException ProfileNotFound() => new(
        ProfileStorageError.ProfileNotFound,
        "The requested profile was not found.");

    private static ProfileStorageException InvalidMetadata() => new(
        ProfileStorageError.InvalidStoredMetadata,
        "Authenticated profile metadata is invalid.");

    private static ProfileStorageException MixedStorage() => new(
        ProfileStorageError.MixedOrDowngradedStorage,
        "The profile store contains mixed or downgraded records.");

    private static void Zero(params byte[]?[] buffers)
    {
        foreach (var buffer in buffers)
        {
            if (buffer is not null)
            {
                CryptographicOperations.ZeroMemory(buffer);
            }
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
    }

    private sealed record StorageMarker(string Magic, int Version);
    private sealed record ManifestRecord(IReadOnlyList<Profile> Profiles);
    private sealed record SelectionRecord(Guid? SelectedProfileId);
}
