using System.Text;
using Target.Windows.Runtime;
using Xunit;

namespace Target.Windows.Tests;

public sealed class WindowsSingBoxRuntimeTests
{
    [Fact]
    public async Task CheckAlwaysPrecedesRunAndSuccessfulLaunchRecordsFullIdentity()
    {
        using var fixture = new RuntimeLifecycleFixture();
        await using var runtime = fixture.CreateRuntime();

        var status = await runtime.StartAsync();

        Assert.True(status.IsRunning);
        Assert.Equal(["version", "check", "run"], fixture.Operations);
        var read = fixture.RecordStore.Read();
        Assert.Equal(RuntimeOwnershipReadKind.ValidRecord, read.Kind);
        var record = Assert.IsType<RuntimeOwnershipRecord>(read.Record);
        Assert.Equal(fixture.Process.Identity.ProcessId, record.ProcessId);
        Assert.Equal(fixture.Process.Identity.CreationTimeFileTimeUtc, record.ProcessCreationTimeFileTimeUtc);
        Assert.Equal(fixture.EngineLocation.ExecutablePath, record.ExecutablePath, ignoreCase: true);
        Assert.Equal(fixture.Profile.ProfileId, record.ProfileId);
        Assert.Equal(1, record.ProfileRevision);
        Assert.Equal("127.0.0.1", record.PrimaryHost);
        Assert.InRange(record.PrimaryPort, 49_152, 65_535);
        Assert.Equal(64, record.ExecutableSha256.Length);
        Assert.Equal(64, record.SourceConfigurationSha256.Length);
        Assert.Equal(64, record.RuntimeConfigurationSha256.Length);
        Assert.True(fixture.ConfigurationStore.ExistsVerified(
            record.RuntimeConfigurationId,
            record.RuntimeConfigurationSha256));
    }

    [Fact]
    public async Task CheckFailureDoesNotLaunchAndCleansPlaintextArtifact()
    {
        using var fixture = new RuntimeLifecycleFixture();
        fixture.Commands.CheckResult = new BoundedCommandResult(1, string.Empty, "bounded", false);
        await using var runtime = fixture.CreateRuntime();

        var error = await Assert.ThrowsAsync<RuntimeOperationException>(() => runtime.StartAsync());

        Assert.Equal(RuntimeFailureReason.ConfigurationCheckFailed, error.Reason);
        Assert.Equal(0, fixture.Launcher.Calls);
        Assert.Equal(RuntimeOwnershipReadKind.NoRecord, fixture.RecordStore.Read().Kind);
        Assert.Empty(Directory.Exists(fixture.RuntimeRoot)
            ? Directory.EnumerateFiles(fixture.RuntimeRoot, "*.json")
            : []);
    }

    [Fact]
    public async Task ReadinessTimeoutCleansOnlyTheExactLaunchedChild()
    {
        using var fixture = new RuntimeLifecycleFixture();
        fixture.Readiness.IsListening = false;
        await using var runtime = fixture.CreateRuntime(
            readinessTimeout: TimeSpan.FromMilliseconds(25),
            pollInterval: TimeSpan.FromMilliseconds(5));

        var error = await Assert.ThrowsAsync<RuntimeOperationException>(() => runtime.StartAsync());

        Assert.Equal(RuntimeFailureReason.ReadinessTimedOut, error.Reason);
        Assert.Equal(1, fixture.Process.FailedLaunchTerminationCalls);
        Assert.Equal(0, fixture.Terminator.Calls);
        Assert.Equal(RuntimeOwnershipReadKind.NoRecord, fixture.RecordStore.Read().Kind);
        Assert.False(Directory.Exists(fixture.RuntimeRoot));
    }

    [Fact]
    public async Task EarlyExitCleansRecordAndConfigurationWithoutPidTerminator()
    {
        using var fixture = new RuntimeLifecycleFixture();
        fixture.Process.HasExitedValue = true;
        await using var runtime = fixture.CreateRuntime();

        var error = await Assert.ThrowsAsync<RuntimeOperationException>(() => runtime.StartAsync());

        Assert.Equal(RuntimeFailureReason.ProcessExitedDuringLaunch, error.Reason);
        Assert.Equal(0, fixture.Terminator.Calls);
        Assert.Equal(RuntimeOwnershipReadKind.NoRecord, fixture.RecordStore.Read().Kind);
        Assert.False(Directory.Exists(fixture.RuntimeRoot));
    }

    [Fact]
    public async Task DuplicateStartIsRefusedWithoutSecondLaunch()
    {
        using var fixture = new RuntimeLifecycleFixture();
        await using var runtime = fixture.CreateRuntime();
        await runtime.StartAsync();

        var error = await Assert.ThrowsAsync<RuntimeOperationException>(() => runtime.StartAsync());

        Assert.Equal(RuntimeFailureReason.DuplicateRuntime, error.Reason);
        Assert.Equal(1, fixture.Launcher.Calls);
    }

    [Fact]
    public async Task LiveUnprovenRecordPreventsCompetingStart()
    {
        using var fixture = new RuntimeLifecycleFixture();
        fixture.SeedOwnedRecord();
        fixture.Inspector.Current = WindowsProcessInspection.Found(
            fixture.Snapshot with { CreationTimeFileTimeUtc = fixture.Snapshot.CreationTimeFileTimeUtc + 1 });
        await using var runtime = fixture.CreateRuntime();

        var error = await Assert.ThrowsAsync<RuntimeOperationException>(() => runtime.StartAsync());

        Assert.Equal(RuntimeFailureReason.LiveRuntimeUnproven, error.Reason);
        Assert.Equal(0, fixture.Launcher.Calls);
        Assert.Equal(RuntimeOwnershipReadKind.ValidRecord, fixture.RecordStore.Read().Kind);
    }

    [Fact]
    public async Task StaleExitedRecordMayBeClearedBeforeStart()
    {
        using var fixture = new RuntimeLifecycleFixture();
        fixture.SeedOwnedRecord();
        fixture.Inspector.Current = WindowsProcessInspection.NotFound;
        fixture.Launcher.OnLaunch = () => fixture.Inspector.Current = WindowsProcessInspection.Found(fixture.Snapshot);
        await using var runtime = fixture.CreateRuntime();

        var status = await runtime.StartAsync();

        Assert.True(status.IsRunning);
        Assert.Equal(1, fixture.Launcher.Calls);
    }

    [Fact]
    public async Task VerifiedStopReprovesThenCleansRecordAndConfiguration()
    {
        using var fixture = new RuntimeLifecycleFixture();
        fixture.Terminator.OnTerminate = () => fixture.Inspector.Current = WindowsProcessInspection.NotFound;
        await using var runtime = fixture.CreateRuntime();
        await runtime.StartAsync();

        var status = await runtime.StopAsync();

        Assert.Equal(RuntimeDispositionKind.NoRecord, status.Disposition);
        Assert.Equal(1, fixture.Terminator.Calls);
        Assert.Equal(RuntimeOwnershipReadKind.NoRecord, fixture.RecordStore.Read().Kind);
        Assert.False(Directory.Exists(fixture.RuntimeRoot));
    }

    [Fact]
    public async Task StopDoesNotInvokeTerminatorWhenImmediateReproofFails()
    {
        using var fixture = new RuntimeLifecycleFixture();
        fixture.SeedOwnedRecord();
        fixture.Inspector.Results.Enqueue(WindowsProcessInspection.Found(fixture.Snapshot));
        fixture.Inspector.Results.Enqueue(WindowsProcessInspection.Found(
            fixture.Snapshot with { CreationTimeFileTimeUtc = fixture.Snapshot.CreationTimeFileTimeUtc + 1 }));
        await using var runtime = fixture.CreateRuntime();

        var error = await Assert.ThrowsAsync<RuntimeOperationException>(() => runtime.StopAsync());

        Assert.Equal(RuntimeFailureReason.LiveRuntimeUnproven, error.Reason);
        Assert.Equal(0, fixture.Terminator.Calls);
        Assert.Equal(RuntimeOwnershipReadKind.ValidRecord, fixture.RecordStore.Read().Kind);
        Assert.True(fixture.ConfigurationStore.ExistsVerified(
            fixture.Record.RuntimeConfigurationId,
            fixture.Record.RuntimeConfigurationSha256));
    }

    [Fact]
    public async Task PidAloneNeverAuthorizesTermination()
    {
        using var fixture = new RuntimeLifecycleFixture();
        fixture.SeedOwnedRecord();
        fixture.Inspector.Current = WindowsProcessInspection.Found(
            fixture.Snapshot with { ExecutableSha256 = new string('0', 64) });
        await using var runtime = fixture.CreateRuntime();

        var error = await Assert.ThrowsAsync<RuntimeOperationException>(() => runtime.StopAsync());

        Assert.Equal(RuntimeFailureReason.LiveRuntimeUnproven, error.Reason);
        Assert.Equal(0, fixture.Terminator.Calls);
    }
}

internal sealed class RuntimeLifecycleFixture : IDisposable
{
    private readonly TemporaryDirectory directory = new("TargetLifecycleTests");

    public RuntimeLifecycleFixture()
    {
        var executable = Path.Combine(directory.Path, "sing-box.exe");
        File.WriteAllText(executable, "synthetic executable fixture");
        EngineLocation = SingBoxEngineLocation.ForTesting(executable);
        RuntimeRoot = Path.Combine(directory.Path, "runtime");
        ConfigurationStore = RuntimeConfigurationStore.ForTesting(RuntimeRoot);
        RecordStore = RuntimeOwnershipStore.ForTesting(RuntimeRoot);
        Profile = new ProfileFixture(Encoding.UTF8.GetBytes(
            """{"outbounds":[{"type":"direct","tag":"direct"}]}"""));
        Commands = new FakeCommands { Operations = Operations };
        Inspector = new FakeProcessInspector();
        Readiness = new FakeReadinessProbe { IsListening = true };
        Process = new FakeTargetRuntimeProcess(new TargetProcessIdentity(
            7_777,
            987_654_321,
            EngineLocation.ExecutablePath));
        var executableSha256 = SingBoxEngineDiscovery.Sha256(EngineLocation.ExecutablePath);
        Snapshot = new WindowsProcessSnapshot(
            Process.Identity.ProcessId,
            Process.Identity.CreationTimeFileTimeUtc,
            EngineLocation.ExecutablePath,
            executableSha256);
        Inspector.Current = WindowsProcessInspection.Found(Snapshot);
        Launcher = new FakeProcessLauncher(Process, Operations)
        {
            OnLaunch = () => Inspector.Current = WindowsProcessInspection.Found(Snapshot)
        };
        Terminator = new FakeTerminator();
        var prepared = new RuntimeConfigurationPreparer(new SequencePortAllocator(51_301)).Prepare(Profile.Store);
        Artifact = ConfigurationStore.Write(prepared.RuntimeConfigurationId, prepared.Data);
        Record = new RuntimeOwnershipRecord(
            Process.Identity.ProcessId,
            Process.Identity.CreationTimeFileTimeUtc,
            EngineLocation.ExecutablePath,
            executableSha256,
            prepared.ProfileId,
            prepared.ProfileRevision,
            prepared.SourceConfigurationSha256,
            prepared.RuntimeConfigurationId,
            prepared.RuntimeConfigurationSha256,
            prepared.PrimaryHost,
            prepared.PrimaryPort,
            DateTimeOffset.UtcNow);
        ConfigurationStore.Delete(Artifact.Id);
    }

    public List<string> Operations { get; } = [];
    public string RuntimeRoot { get; }
    public SingBoxEngineLocation EngineLocation { get; }
    public RuntimeConfigurationStore ConfigurationStore { get; }
    public RuntimeOwnershipStore RecordStore { get; }
    public ProfileFixture Profile { get; }
    public FakeCommands Commands { get; }
    public FakeProcessInspector Inspector { get; }
    public FakeReadinessProbe Readiness { get; }
    public FakeTargetRuntimeProcess Process { get; }
    public WindowsProcessSnapshot Snapshot { get; }
    public FakeProcessLauncher Launcher { get; }
    public FakeTerminator Terminator { get; }
    public RuntimeConfigurationArtifact Artifact { get; }
    public RuntimeOwnershipRecord Record { get; private set; }

    public WindowsSingBoxRuntime CreateRuntime(
        TimeSpan? readinessTimeout = null,
        TimeSpan? pollInterval = null)
    {
        return new WindowsSingBoxRuntime(
            Profile.Store,
            EngineLocation,
            commands: Commands,
            processLauncher: Launcher,
            configurationPreparer: new RuntimeConfigurationPreparer(new SequencePortAllocator(51_302)),
            configurationStore: ConfigurationStore,
            ownershipStore: RecordStore,
            processInspector: Inspector,
            readinessProbe: Readiness,
            processTerminator: Terminator,
            readinessTimeout: readinessTimeout ?? TimeSpan.FromSeconds(1),
            pollInterval: pollInterval ?? TimeSpan.FromMilliseconds(5));
    }

    public void SeedOwnedRecord()
    {
        ConfigurationStore.Write(Record.RuntimeConfigurationId, """{"synthetic":true}"""u8);
        var bytes = File.ReadAllBytes(Path.Combine(RuntimeRoot, $"{Record.RuntimeConfigurationId:D}.json"));
        var corrected = Record with
        {
            RuntimeConfigurationSha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant()
        };
        RecordStore.Save(corrected);
        Record = corrected;
    }

    public void Dispose()
    {
        Profile.Dispose();
        directory.Dispose();
    }
}

internal sealed class FakeTargetRuntimeProcess(TargetProcessIdentity identity) : ITargetRuntimeProcess
{
    public TargetProcessIdentity Identity { get; } = identity;
    public bool HasExitedValue { get; set; }
    public int FailedLaunchTerminationCalls { get; private set; }
    public bool Disposed { get; private set; }
    public bool HasExited => HasExitedValue;

    public Task WaitForExitAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public void TerminateForFailedLaunch()
    {
        FailedLaunchTerminationCalls++;
        HasExitedValue = true;
    }

    public void Dispose() => Disposed = true;
}

internal sealed class FakeProcessLauncher(
    FakeTargetRuntimeProcess process,
    List<string> operations) : ISingBoxProcessLauncher
{
    public int Calls { get; private set; }
    public Action? OnLaunch { get; set; }

    public ITargetRuntimeProcess LaunchRun(string runtimeConfigurationPath)
    {
        Assert.True(File.Exists(runtimeConfigurationPath));
        Calls++;
        operations.Add("run");
        OnLaunch?.Invoke();
        return process;
    }
}

internal sealed class FakeTerminator : IOwnedProcessTerminator
{
    public int Calls { get; private set; }
    public Action? OnTerminate { get; set; }
    public bool Result { get; set; } = true;

    public Task<bool> TerminateAsync(RuntimeOwnershipRecord record, CancellationToken cancellationToken)
    {
        Calls++;
        OnTerminate?.Invoke();
        return Task.FromResult(Result);
    }
}
