using Target.Windows.Runtime;
using Xunit;

namespace Target.Windows.Tests;

public sealed class RuntimeOwnershipTests
{
    [Fact]
    public async Task MatchingRecordProcessArtifactAndReadinessAreOwned()
    {
        using var fixture = new OwnershipFixture();

        var disposition = await fixture.Ownership.GetDispositionAsync();

        Assert.Equal(RuntimeDispositionKind.OwnedRunning, disposition.Kind);
        Assert.Equal(fixture.Record, disposition.Record);
    }

    [Fact]
    public async Task ConfirmedMissingPidIsProcessExited()
    {
        using var fixture = new OwnershipFixture();
        fixture.Inspector.Current = WindowsProcessInspection.NotFound;

        var disposition = await fixture.Ownership.GetDispositionAsync();

        Assert.Equal(RuntimeDispositionKind.ProcessExited, disposition.Kind);
        Assert.Equal(fixture.Record, disposition.Record);
    }

    [Theory]
    [InlineData("start")]
    [InlineData("path")]
    [InlineData("fingerprint")]
    public async Task ReusedPidAndExecutableMismatchesAreLiveUnproven(string mismatch)
    {
        using var fixture = new OwnershipFixture();
        var snapshot = fixture.Snapshot;
        fixture.Inspector.Current = mismatch switch
        {
            "start" => WindowsProcessInspection.Found(snapshot with { CreationTimeFileTimeUtc = snapshot.CreationTimeFileTimeUtc + 1 }),
            "path" => WindowsProcessInspection.Found(snapshot with { ExecutablePath = Path.Combine(fixture.Directory.Path, "other.exe") }),
            "fingerprint" => WindowsProcessInspection.Found(snapshot with { ExecutableSha256 = new string('0', 64) }),
            _ => throw new InvalidOperationException()
        };

        var disposition = await fixture.Ownership.GetDispositionAsync();

        Assert.Equal(RuntimeDispositionKind.LiveUnproven, disposition.Kind);
    }

    [Fact]
    public async Task UnreadableLivePidIsNotTreatedAsExited()
    {
        using var fixture = new OwnershipFixture();
        fixture.Inspector.Current = WindowsProcessInspection.Unreadable;

        var disposition = await fixture.Ownership.GetDispositionAsync();

        Assert.Equal(RuntimeDispositionKind.LiveUnproven, disposition.Kind);
    }

    [Fact]
    public async Task RuntimeConfigurationFingerprintDriftIsLiveUnproven()
    {
        using var fixture = new OwnershipFixture();
        File.WriteAllText(fixture.Artifact.Path, "changed synthetic configuration");

        var disposition = await fixture.Ownership.GetDispositionAsync();

        Assert.Equal(RuntimeDispositionKind.LiveUnproven, disposition.Kind);
    }

    [Fact]
    public async Task MalformedRecordFailsClosed()
    {
        using var fixture = new OwnershipFixture(saveRecord: false);
        File.WriteAllText(Path.Combine(fixture.RuntimeRoot, "runtime-record.json"), "{ malformed");

        var disposition = await fixture.Ownership.GetDispositionAsync();

        Assert.Equal(RuntimeDispositionKind.LiveUnproven, disposition.Kind);
        Assert.Null(disposition.Record);
    }

    [Fact]
    public async Task ParseableButInvalidRecordCannotBeClearedAsExited()
    {
        using var fixture = new OwnershipFixture(saveRecord: false);
        var invalid = fixture.Record with { ExecutableSha256 = "invalid" };
        fixture.RecordStore.Save(invalid);
        fixture.Inspector.Current = WindowsProcessInspection.NotFound;

        var disposition = await fixture.Ownership.GetDispositionAsync();

        Assert.Equal(RuntimeDispositionKind.LiveUnproven, disposition.Kind);
        Assert.Equal(invalid, disposition.Record);
        Assert.False(fixture.Ownership.ClearExitedRecord(invalid));
        Assert.Equal(RuntimeOwnershipReadKind.ValidRecord, fixture.RecordStore.Read().Kind);
    }
}

internal sealed class OwnershipFixture : IDisposable
{
    public OwnershipFixture(bool saveRecord = true)
    {
        Directory = new TemporaryDirectory("TargetOwnershipTests");
        var executable = Path.Combine(Directory.Path, "sing-box.exe");
        File.WriteAllText(executable, "synthetic executable fixture");
        EngineLocation = SingBoxEngineLocation.ForTesting(executable);
        RuntimeRoot = Path.Combine(Directory.Path, "runtime");
        ConfigurationStore = RuntimeConfigurationStore.ForTesting(RuntimeRoot);
        RecordStore = RuntimeOwnershipStore.ForTesting(RuntimeRoot);
        Artifact = ConfigurationStore.Write(Guid.NewGuid(), "{}"u8);
        var executableSha256 = SingBoxEngineDiscovery.Sha256(executable);
        Record = new RuntimeOwnershipRecord(
            4242,
            123_456_789,
            EngineLocation.ExecutablePath,
            executableSha256,
            Guid.NewGuid(),
            1,
            RuntimeConfigurationStoreTestExtensions.Sha256ForTests("source"u8),
            Artifact.Id,
            Artifact.Sha256,
            "127.0.0.1",
            51_242,
            DateTimeOffset.UtcNow);
        Snapshot = new WindowsProcessSnapshot(
            Record.ProcessId,
            Record.ProcessCreationTimeFileTimeUtc,
            Record.ExecutablePath,
            Record.ExecutableSha256);
        Inspector = new FakeProcessInspector { Current = WindowsProcessInspection.Found(Snapshot) };
        Readiness = new FakeReadinessProbe { IsListening = true };
        Ownership = new RuntimeOwnership(
            EngineLocation,
            RecordStore,
            ConfigurationStore,
            Inspector,
            Readiness);
        if (saveRecord)
        {
            RecordStore.Save(Record);
        }
    }

    public TemporaryDirectory Directory { get; }
    public string RuntimeRoot { get; }
    public SingBoxEngineLocation EngineLocation { get; }
    public RuntimeConfigurationStore ConfigurationStore { get; }
    public RuntimeOwnershipStore RecordStore { get; }
    public RuntimeConfigurationArtifact Artifact { get; }
    public RuntimeOwnershipRecord Record { get; }
    public WindowsProcessSnapshot Snapshot { get; }
    public FakeProcessInspector Inspector { get; }
    public FakeReadinessProbe Readiness { get; }
    public RuntimeOwnership Ownership { get; }
    public void Dispose() => Directory.Dispose();
}

internal sealed class FakeProcessInspector : IWindowsProcessInspector
{
    public WindowsProcessInspection Current { get; set; } = WindowsProcessInspection.NotFound;
    public Queue<WindowsProcessInspection> Results { get; } = new();
    public int Calls { get; private set; }

    public WindowsProcessInspection Inspect(int processId)
    {
        Calls++;
        return Results.Count > 0 ? Results.Dequeue() : Current;
    }
}

internal sealed class FakeReadinessProbe : ILoopbackReadinessProbe
{
    public bool IsListening { get; set; }
    public int Calls { get; private set; }

    public Task<bool> IsListeningAsync(string host, int port, CancellationToken cancellationToken)
    {
        Calls++;
        return Task.FromResult(IsListening);
    }
}

internal static class RuntimeConfigurationStoreTestExtensions
{
    public static string Sha256ForTests(ReadOnlySpan<byte> content) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(content)).ToLowerInvariant();
}
