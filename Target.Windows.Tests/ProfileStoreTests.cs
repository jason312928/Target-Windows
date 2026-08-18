using System.Security.Cryptography;
using System.Text;
using Target.Windows.Core;
using Xunit;

namespace Target.Windows.Tests;

public sealed class ProfileStoreTests
{
    [Fact]
    public void EmptyAndWhitespaceNamesAreRejected()
    {
        using var fixture = new StoreFixture();
        Assert.Equal(ProfileStorageError.InvalidProfileName, Assert.Throws<ProfileStorageException>(() => fixture.Store.CreateProfile(" ", "{}"u8)).Error);
        Assert.Equal(ProfileStorageError.InvalidProfileName, Assert.Throws<ProfileStorageException>(() => fixture.Store.CreateProfile("  \t", "{}"u8)).Error);
    }

    [Fact]
    public void CreateSelectPersistAndReopenPreserveOpaqueConfiguration()
    {
        using var fixture = new StoreFixture();
        var firstConfiguration = Encoding.UTF8.GetBytes("{\"unknown\": [3, 2, 1], \"spacing\":true}");
        var secondConfiguration = Encoding.UTF8.GetBytes(" { \"unknown\" : [3,2,1] } ");
        var first = fixture.Store.CreateProfile("  Main  ", firstConfiguration);
        Assert.Equal("Main", first.Name);
        Assert.Equal(first.Id, fixture.Store.SelectedProfileId);
        Assert.Equal(firstConfiguration, fixture.Store.ReadCurrentConfiguration(first.Id).Content);

        var second = fixture.Store.CreateProfile("Secondary", "{}"u8);
        fixture.Store.SelectProfile(second.Id);
        Assert.Equal(second.Id, fixture.Store.SelectedProfileId);
        var updated = fixture.Store.PersistConfiguration(first.Id, secondConfiguration);
        Assert.Equal(2, updated.CurrentRevision);
        Assert.Equal(secondConfiguration, fixture.Store.ReadCurrentConfiguration(first.Id).Content);

        fixture.Store.Dispose();
        using var reopened = fixture.Open();
        Assert.Equal(second.Id, reopened.SelectedProfileId);
        var reopenedFirst = Assert.Single(reopened.ListProfiles(), profile => profile.Id == first.Id);
        Assert.Equal(2, reopenedFirst.CurrentRevision);
        Assert.Equal(secondConfiguration, reopened.ReadCurrentConfiguration(first.Id).Content);
    }

    [Fact]
    public void RecordsAreEncryptedAndIndependentWritesUseFreshNonces()
    {
        using var fixture = new StoreFixture();
        var marker = "synthetic-profile-marker";
        var profile = fixture.Store.CreateProfile(marker, Encoding.UTF8.GetBytes("{\"synthetic\":true}"));
        fixture.Store.SelectProfile(profile.Id);

        var manifest = File.ReadAllBytes(Path.Combine(fixture.Root, "profiles.json"));
        var selection = File.ReadAllBytes(Path.Combine(fixture.Root, "selected-profile.json"));
        var current = File.ReadAllBytes(Path.Combine(fixture.Root, profile.Id.ToString("D"), "config.json"));
        var revision = File.ReadAllBytes(Path.Combine(fixture.Root, profile.Id.ToString("D"), "versions", "1.json"));
        AssertEncryptedEnvelope(manifest);
        AssertEncryptedEnvelope(selection);
        AssertEncryptedEnvelope(current);
        AssertEncryptedEnvelope(revision);
        Assert.False(ContainsSubsequence(manifest, Encoding.UTF8.GetBytes(marker)));
        Assert.False(ContainsSubsequence(current, Encoding.UTF8.GetBytes("synthetic")));
        Assert.False(selection.AsSpan().SequenceEqual(revision));
        var selectionBefore = selection.ToArray();
        fixture.Store.SelectProfile(profile.Id);
        Assert.False(selectionBefore.AsSpan().SequenceEqual(File.ReadAllBytes(Path.Combine(fixture.Root, "selected-profile.json"))));
    }

    [Fact]
    public void TamperingWrongKeyAndPathSubstitutionFailClosed()
    {
        using var fixture = new StoreFixture();
        var profile = fixture.Store.CreateProfile("Main", "{}"u8);
        fixture.Store.Dispose();
        var currentPath = Path.Combine(fixture.Root, profile.Id.ToString("D"), "config.json");
        var original = File.ReadAllBytes(currentPath);
        var current = original.ToArray();
        current[^1] ^= 0x01;
        File.WriteAllBytes(currentPath, current);
        var tampered = Assert.Throws<ProfileStorageException>(() => fixture.Open());
        Assert.Equal(ProfileStorageError.AuthenticationFailure, tampered.Error);

        File.WriteAllBytes(currentPath, original);
        var wrongKey = Assert.Throws<ProfileStorageException>(() => fixture.Open(new FixedKeyProvider(RandomNumberGenerator.GetBytes(32))));
        Assert.Equal(ProfileStorageError.AuthenticationFailure, wrongKey.Error);
    }

    [Fact]
    public void MissingOrMalformedKeyDoesNotCreateReplacement()
    {
        using var fixture = new StoreFixture();
        fixture.Store.CreateProfile("Main", "{}"u8);
        fixture.Store.Dispose();
        var createCountBeforeReopen = fixture.KeyProvider.CreateCount;
        fixture.KeyProvider.AllowKey = false;
        Assert.Equal(ProfileStorageError.ProtectedKeyMissing, Assert.Throws<ProfileStorageException>(() => fixture.Open()).Error);
        Assert.Equal(createCountBeforeReopen, fixture.KeyProvider.CreateCount);
    }

    [Fact]
    public void PlaintextDowngradeAndUnsupportedEnvelopeFailClosed()
    {
        using var fixture = new StoreFixture();
        fixture.Store.CreateProfile("Main", "{}"u8);
        fixture.Store.Dispose();
        File.WriteAllText(Path.Combine(fixture.Root, "profiles.json"), "{\"Profiles\":[]}");
        Assert.Equal(ProfileStorageError.MixedOrDowngradedStorage, Assert.Throws<ProfileStorageException>(() => fixture.Open()).Error);
    }

    [Fact]
    public void RecordSubstitutionAndUnsupportedVersionFailClosed()
    {
        using var fixture = new StoreFixture();
        var profile = fixture.Store.CreateProfile("Main", "{}"u8);
        fixture.Store.PersistConfiguration(profile.Id, "{\"v\":2}"u8);
        fixture.Store.Dispose();
        var versions = Path.Combine(fixture.Root, profile.Id.ToString("D"), "versions");
        File.Copy(Path.Combine(versions, "1.json"), Path.Combine(versions, "2.json"), overwrite: true);
        Assert.Equal(ProfileStorageError.AadBindingMismatch, Assert.Throws<ProfileStorageException>(() => fixture.Open()).Error);

        File.Copy(Path.Combine(versions, "1.json"), Path.Combine(versions, "2.json"), overwrite: true);
        var envelope = File.ReadAllBytes(Path.Combine(versions, "1.json"));
        envelope[8] = 2;
        File.WriteAllBytes(Path.Combine(versions, "1.json"), envelope);
        Assert.Equal(ProfileStorageError.UnsupportedStorageVersion, Assert.Throws<ProfileStorageException>(() => fixture.Open()).Error);
    }

    [Fact]
    public void ProfilePathAndRecordKindBindingsRejectSubstitution()
    {
        using var fixture = new StoreFixture();
        var first = fixture.Store.CreateProfile("First", "{\"profile\":1}"u8);
        var second = fixture.Store.CreateProfile("Second", "{\"profile\":2}"u8);
        fixture.Store.Dispose();
        var firstCurrent = Path.Combine(fixture.Root, first.Id.ToString("D"), "config.json");
        var secondCurrent = Path.Combine(fixture.Root, second.Id.ToString("D"), "config.json");
        var secondOriginal = File.ReadAllBytes(secondCurrent);
        File.Copy(firstCurrent, secondCurrent, overwrite: true);
        Assert.Equal(ProfileStorageError.AadBindingMismatch, Assert.Throws<ProfileStorageException>(() => fixture.Open()).Error);

        File.WriteAllBytes(secondCurrent, secondOriginal);
        File.Copy(firstCurrent, Path.Combine(fixture.Root, first.Id.ToString("D"), "versions", "1.json"), overwrite: true);
        Assert.Equal(ProfileStorageError.AadBindingMismatch, Assert.Throws<ProfileStorageException>(() => fixture.Open()).Error);
    }

    [Fact]
    public void FailedManifestCommitLeavesPreviousCurrentConfigurationUsable()
    {
        using var fixture = new StoreFixture();
        var profile = fixture.Store.CreateProfile("Main", "{\"v\":1}"u8);
        fixture.Store.Dispose();
        using var failingStore = fixture.Open(new FixedKeyProvider(fixture.KeyProvider.Key), new FailingWriter(Path.Combine(fixture.Root, "profiles.json")));
        Assert.Equal(ProfileStorageError.PersistenceFailure, Assert.Throws<ProfileStorageException>(() => failingStore.PersistConfiguration(profile.Id, "{\"v\":2}"u8)).Error);
        failingStore.Dispose();
        using var reopened = fixture.Open();
        Assert.Equal(Encoding.UTF8.GetBytes("{\"v\":1}"), reopened.ReadCurrentConfiguration(profile.Id).Content);
    }

    [Fact]
    public void DpapiCurrentUserRoundTripUsesOnlyProtectedDiskMaterial()
    {
        var root = Path.Combine(Path.GetTempPath(), "TargetDpapiTests", Guid.NewGuid().ToString("N"));
        var keyPath = Path.Combine(root, "profile-master-key-v1.dpapi");
        Directory.CreateDirectory(root);
        try
        {
            var provider = new DpapiProfileEncryptionKeyProvider(keyPath);
            var first = provider.GetKey(ProfileKeyAccess.InitializeNewStore);
            var persisted = File.ReadAllBytes(keyPath);
            var second = provider.GetKey(ProfileKeyAccess.OpenExistingStore);
            Assert.Equal(first, second);
            Assert.False(first.AsSpan().SequenceEqual(persisted));
            CryptographicOperations.ZeroMemory(first);
            CryptographicOperations.ZeroMemory(second);
            File.WriteAllBytes(keyPath, [1, 2, 3]);
            Assert.Equal(ProfileStorageError.ProtectedKeyInvalid, Assert.Throws<ProfileStorageException>(() => provider.GetKey(ProfileKeyAccess.OpenExistingStore)).Error);
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch (DirectoryNotFoundException) { }
        }
    }

    private sealed class StoreFixture : IDisposable
    {
        public StoreFixture()
        {
            Root = Path.Combine(Path.GetTempPath(), "TargetProfileTests", Guid.NewGuid().ToString("N"));
            KeyProvider = new FixedKeyProvider(RandomNumberGenerator.GetBytes(32));
            Store = Open();
        }

        public string Root { get; }
        public FixedKeyProvider KeyProvider { get; }
        public ProfileStore Store { get; set; }
        public ProfileStore Open(IProfileEncryptionKeyProvider? provider = null, IProfileFileWriter? writer = null)
        {
            return ProfileStore.Open(Root, provider ?? KeyProvider, writer);
        }

        public void Dispose()
        {
            Store.Dispose();
            try { Directory.Delete(Root, recursive: true); } catch (DirectoryNotFoundException) { }
        }
    }

    private sealed class FixedKeyProvider(byte[] key) : IProfileEncryptionKeyProvider
    {
        public byte[] Key => key;
        public bool AllowKey { get; set; } = true;
        public int CreateCount { get; private set; }

        public byte[] GetKey(ProfileKeyAccess access)
        {
            if (!AllowKey && access == ProfileKeyAccess.OpenExistingStore)
            {
                throw new ProfileStorageException(ProfileStorageError.ProtectedKeyMissing, "The protected profile encryption key is missing.");
            }

            if (access == ProfileKeyAccess.InitializeNewStore)
            {
                CreateCount++;
            }

            return key.ToArray();
        }
    }

    private static bool ContainsSubsequence(byte[] haystack, byte[] needle)
    {
        for (var start = 0; start <= haystack.Length - needle.Length; start++)
        {
            if (haystack.AsSpan(start, needle.Length).SequenceEqual(needle))
            {
                return true;
            }
        }

        return false;
    }

    private static void AssertEncryptedEnvelope(byte[] content)
    {
        Assert.True(content.Length > 72);
        Assert.Equal("TWPRFENC", Encoding.ASCII.GetString(content, 0, 8));
    }

    private sealed class FailingWriter(string failingPath) : IProfileFileWriter
    {
        private readonly DurableProfileFileWriter inner = new();
        private bool failed;

        public void WriteAtomically(string path, ReadOnlySpan<byte> content)
        {
            if (!failed && string.Equals(path, failingPath, StringComparison.OrdinalIgnoreCase))
            {
                failed = true;
                throw new ProfileStorageException(ProfileStorageError.PersistenceFailure, "injected persistence failure");
            }

            inner.WriteAtomically(path, content);
        }
    }
}
