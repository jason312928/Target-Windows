using System.Security.Cryptography;
using Target.Windows.Core;

namespace Target.Windows.Runtime;

public sealed record WindowsSingBoxRuntimeStatus(
    RuntimeDispositionKind Disposition,
    string? EngineVersion,
    Guid? ProfileId,
    long? ProfileRevision,
    string? PrimaryHost,
    int? PrimaryPort)
{
    public bool IsRunning => Disposition == RuntimeDispositionKind.OwnedRunning;
}

public sealed class WindowsSingBoxRuntime : IAsyncDisposable
{
    private readonly SemaphoreSlim lifecycleGate = new(1, 1);
    private readonly ProfileStore profileStore;
    private readonly SingBoxEngineLocation engineLocation;
    private readonly SingBoxEngineDiscovery engineDiscovery;
    private readonly ISingBoxCommandExecutor commands;
    private readonly ISingBoxProcessLauncher processLauncher;
    private readonly RuntimeConfigurationPreparer configurationPreparer;
    private readonly RuntimeConfigurationStore configurationStore;
    private readonly RuntimeOwnership ownership;
    private readonly ILoopbackReadinessProbe readinessProbe;
    private readonly IOwnedProcessTerminator processTerminator;
    private readonly RuntimeLifecycleLock runtimeLifecycleLock;
    private readonly TimeProvider timeProvider;
    private readonly TimeSpan readinessTimeout;
    private readonly TimeSpan pollInterval;
    private ITargetRuntimeProcess? retainedProcess;
    private bool disposed;

    public WindowsSingBoxRuntime(
        ProfileStore profileStore,
        SingBoxEngineLocation? engineLocation = null,
        SingBoxEngineDiscovery? engineDiscovery = null,
        ISingBoxCommandExecutor? commands = null,
        ISingBoxProcessLauncher? processLauncher = null,
        RuntimeConfigurationPreparer? configurationPreparer = null,
        RuntimeConfigurationStore? configurationStore = null,
        RuntimeOwnershipStore? ownershipStore = null,
        IWindowsProcessInspector? processInspector = null,
        ILoopbackReadinessProbe? readinessProbe = null,
        IOwnedProcessTerminator? processTerminator = null,
        TimeProvider? timeProvider = null,
        TimeSpan? readinessTimeout = null,
        TimeSpan? pollInterval = null)
    {
        this.profileStore = profileStore ?? throw new ArgumentNullException(nameof(profileStore));
        this.engineLocation = engineLocation ?? SingBoxEngineLocation.Production();
        var defaultCommands = new WindowsSingBoxCommandExecutor(this.engineLocation);
        this.commands = commands ?? defaultCommands;
        this.processLauncher = processLauncher ?? (this.commands as ISingBoxProcessLauncher ?? defaultCommands);
        this.engineDiscovery = engineDiscovery ?? new SingBoxEngineDiscovery(this.engineLocation, this.commands);
        this.configurationPreparer = configurationPreparer ?? new RuntimeConfigurationPreparer();
        this.configurationStore = configurationStore ?? RuntimeConfigurationStore.Production();
        var recordStore = ownershipStore ?? RuntimeOwnershipStore.Production();
        var inspector = processInspector ?? new WindowsProcessInspector();
        this.readinessProbe = readinessProbe ?? new LoopbackTcpReadinessProbe();
        this.ownership = new RuntimeOwnership(
            this.engineLocation,
            recordStore,
            this.configurationStore,
            inspector,
            this.readinessProbe);
        this.processTerminator = processTerminator ?? new WindowsOwnedProcessTerminator(this.engineLocation);
        runtimeLifecycleLock = new RuntimeLifecycleLock(this.engineLocation);
        this.timeProvider = timeProvider ?? TimeProvider.System;
        this.readinessTimeout = readinessTimeout ?? TimeSpan.FromSeconds(10);
        this.pollInterval = pollInterval ?? TimeSpan.FromMilliseconds(100);
        if (this.readinessTimeout <= TimeSpan.Zero || this.readinessTimeout > TimeSpan.FromMinutes(1))
        {
            throw new ArgumentOutOfRangeException(nameof(readinessTimeout));
        }

        if (this.pollInterval <= TimeSpan.Zero || this.pollInterval > TimeSpan.FromSeconds(1))
        {
            throw new ArgumentOutOfRangeException(nameof(pollInterval));
        }
    }

    public async Task<WindowsSingBoxRuntimeStatus> QueryAsync(CancellationToken cancellationToken = default)
    {
        await lifecycleGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var crossProcessLock = await runtimeLifecycleLock.AcquireAsync(cancellationToken).ConfigureAwait(false);
            ThrowIfDisposed();
            var disposition = await ownership.GetDispositionAsync(cancellationToken).ConfigureAwait(false);
            if (disposition.Kind == RuntimeDispositionKind.NoRecord
                && retainedProcess is { HasExited: false })
            {
                disposition = new RuntimeDisposition(RuntimeDispositionKind.LiveUnproven, null);
            }
            disposition = ReconcileExited(disposition);
            var engineStatus = await engineDiscovery.GetStatusAsync(cancellationToken).ConfigureAwait(false);
            return ToStatus(disposition, engineStatus.Version);
        }
        finally
        {
            lifecycleGate.Release();
        }
    }

    public async Task ValidateSelectedConfigurationAsync(CancellationToken cancellationToken = default)
    {
        await lifecycleGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var crossProcessLock = await runtimeLifecycleLock.AcquireAsync(cancellationToken).ConfigureAwait(false);
            ThrowIfDisposed();
            await RequirePinnedEngineAsync(cancellationToken).ConfigureAwait(false);
            var prepared = PrepareConfiguration();
            var artifact = configurationStore.Write(prepared.RuntimeConfigurationId, prepared.Data);
            try
            {
                var check = await commands.CheckAsync(artifact.Path, cancellationToken).ConfigureAwait(false);
                ThrowForCheckFailure(check);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(prepared.Data);
                if (!configurationStore.Delete(artifact.Id))
                {
                    throw new RuntimeOperationException(
                        RuntimeFailureReason.StorageFailure,
                        "The temporary runtime configuration could not be removed.");
                }
            }
        }
        finally
        {
            lifecycleGate.Release();
        }
    }

    public async Task<WindowsSingBoxRuntimeStatus> StartAsync(CancellationToken cancellationToken = default)
    {
        await lifecycleGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var crossProcessLock = await runtimeLifecycleLock.AcquireAsync(cancellationToken).ConfigureAwait(false);
            ThrowIfDisposed();
            var disposition = await ownership.GetDispositionAsync(cancellationToken).ConfigureAwait(false);
            if (disposition.Kind == RuntimeDispositionKind.NoRecord
                && retainedProcess is { HasExited: false })
            {
                disposition = new RuntimeDisposition(RuntimeDispositionKind.LiveUnproven, null);
            }
            switch (disposition.Kind)
            {
                case RuntimeDispositionKind.NoRecord:
                    configurationStore.DeleteUnassociatedArtifacts();
                    break;
                case RuntimeDispositionKind.ProcessExited:
                    if (disposition.Record is null || !ownership.ClearExitedRecord(disposition.Record))
                    {
                        throw new RuntimeOperationException(
                            RuntimeFailureReason.InvalidLifecycle,
                            "The exited runtime evidence could not be reconciled.");
                    }

                    ReleaseRetainedProcess(disposition.Record.ProcessId);
                    break;
                case RuntimeDispositionKind.OwnedRunning:
                    throw new RuntimeOperationException(
                        RuntimeFailureReason.DuplicateRuntime,
                        "A Target-owned runtime is already running.");
                case RuntimeDispositionKind.LiveUnproven:
                    throw new RuntimeOperationException(
                        RuntimeFailureReason.LiveRuntimeUnproven,
                        "A live runtime cannot be proven as Target-owned.");
                default:
                    throw new RuntimeOperationException(RuntimeFailureReason.InvalidLifecycle, "The runtime state is invalid.");
            }

            var version = await RequirePinnedEngineAsync(cancellationToken).ConfigureAwait(false);
            var prepared = PrepareConfiguration();
            var artifact = configurationStore.Write(prepared.RuntimeConfigurationId, prepared.Data);
            ITargetRuntimeProcess? launched = null;
            RuntimeOwnershipRecord? record = null;
            try
            {
                var check = await commands.CheckAsync(artifact.Path, cancellationToken).ConfigureAwait(false);
                ThrowForCheckFailure(check);
                cancellationToken.ThrowIfCancellationRequested();

                var executableSha256 = SingBoxEngineDiscovery.Sha256(engineLocation.ExecutablePath);
                launched = processLauncher.LaunchRun(artifact.Path);
                record = ownership.CreateRecord(
                    launched.Identity,
                    prepared,
                    executableSha256,
                    timeProvider.GetUtcNow());
                ownership.SaveRecord(record);

                await WaitForReadinessAsync(launched, prepared, cancellationToken).ConfigureAwait(false);
                var proof = await ownership.GetDispositionAsync(cancellationToken).ConfigureAwait(false);
                if (proof.Kind != RuntimeDispositionKind.OwnedRunning || proof.Record != record)
                {
                    throw new RuntimeOperationException(
                        RuntimeFailureReason.LaunchFailed,
                        "The launched runtime did not satisfy ownership proof.");
                }

                retainedProcess = launched;
                launched = null;
                return ToStatus(proof, version);
            }
            catch (OperationCanceledException)
            {
                await CleanupFailedLaunchAsync(launched, record, prepared.RuntimeConfigurationId).ConfigureAwait(false);
                throw;
            }
            catch (RuntimeOperationException)
            {
                await CleanupFailedLaunchAsync(launched, record, prepared.RuntimeConfigurationId).ConfigureAwait(false);
                throw;
            }
            catch (Exception exception)
            {
                await CleanupFailedLaunchAsync(launched, record, prepared.RuntimeConfigurationId).ConfigureAwait(false);
                throw new RuntimeOperationException(
                    RuntimeFailureReason.LaunchFailed,
                    "The Target-owned runtime could not be launched.",
                    exception);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(prepared.Data);
            }
        }
        finally
        {
            lifecycleGate.Release();
        }
    }

    public async Task<WindowsSingBoxRuntimeStatus> StopAsync(CancellationToken cancellationToken = default)
    {
        await lifecycleGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var crossProcessLock = await runtimeLifecycleLock.AcquireAsync(cancellationToken).ConfigureAwait(false);
            ThrowIfDisposed();
            var disposition = await ownership.GetDispositionAsync(cancellationToken).ConfigureAwait(false);
            if (disposition.Kind == RuntimeDispositionKind.ProcessExited && disposition.Record is not null)
            {
                if (!ownership.ClearExitedRecord(disposition.Record))
                {
                    throw new RuntimeOperationException(RuntimeFailureReason.InvalidLifecycle, "The exited runtime could not be reconciled.");
                }

                ReleaseRetainedProcess(disposition.Record.ProcessId);
                return ToStatus(new RuntimeDisposition(RuntimeDispositionKind.NoRecord, null), null);
            }

            if (disposition.Kind == RuntimeDispositionKind.LiveUnproven)
            {
                throw new RuntimeOperationException(
                    RuntimeFailureReason.LiveRuntimeUnproven,
                    "Runtime ownership could not be proven; no process was terminated.");
            }

            if (disposition.Kind != RuntimeDispositionKind.OwnedRunning || disposition.Record is null)
            {
                throw new RuntimeOperationException(RuntimeFailureReason.InvalidLifecycle, "No Target-owned runtime is running.");
            }

            var record = disposition.Record;
            cancellationToken.ThrowIfCancellationRequested();

            // Re-proof immediately before entering the only arbitrary-PID termination boundary.
            if (!await ownership.ReproveOwnershipAsync(record, cancellationToken).ConfigureAwait(false))
            {
                throw new RuntimeOperationException(
                    RuntimeFailureReason.LiveRuntimeUnproven,
                    "Runtime ownership changed before stop; no process was terminated.");
            }

            if (!await processTerminator.TerminateAsync(record, cancellationToken).ConfigureAwait(false))
            {
                throw new RuntimeOperationException(RuntimeFailureReason.StopFailed, "The proven Target-owned runtime did not stop.");
            }

            if (!ownership.ClearExitedRecord(record))
            {
                throw new RuntimeOperationException(
                    RuntimeFailureReason.StopFailed,
                    "Runtime exit could not be confirmed; ownership evidence was retained.");
            }

            ReleaseRetainedProcess(record.ProcessId);
            return ToStatus(new RuntimeDisposition(RuntimeDispositionKind.NoRecord, null), null);
        }
        finally
        {
            lifecycleGate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await lifecycleGate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (disposed)
            {
                return;
            }

            // Disposing the app object never broadens process authority. A running
            // engine remains recoverable through the persisted ownership record.
            retainedProcess?.Dispose();
            retainedProcess = null;
            disposed = true;
        }
        finally
        {
            lifecycleGate.Release();
            lifecycleGate.Dispose();
        }
    }

    private RuntimeDisposition ReconcileExited(RuntimeDisposition disposition)
    {
        if (disposition.Kind != RuntimeDispositionKind.ProcessExited || disposition.Record is null)
        {
            return disposition;
        }

        if (!ownership.ClearExitedRecord(disposition.Record))
        {
            return new RuntimeDisposition(RuntimeDispositionKind.LiveUnproven, disposition.Record);
        }

        ReleaseRetainedProcess(disposition.Record.ProcessId);
        return new RuntimeDisposition(RuntimeDispositionKind.NoRecord, null);
    }

    private async Task<string> RequirePinnedEngineAsync(CancellationToken cancellationToken)
    {
        var engine = await engineDiscovery.GetStatusAsync(cancellationToken).ConfigureAwait(false);
        switch (engine.Kind)
        {
            case SingBoxEngineStatusKind.NotInstalled:
                throw new RuntimeOperationException(RuntimeFailureReason.EngineNotInstalled, "The Target-owned sing-box engine is not installed.");
            case SingBoxEngineStatusKind.Invalid:
                throw new RuntimeOperationException(RuntimeFailureReason.EngineInvalid, "The Target-owned sing-box engine is invalid.");
            case SingBoxEngineStatusKind.Installed when engine.Version != SingBoxEngineConstants.PinnedVersion:
                throw new RuntimeOperationException(RuntimeFailureReason.EngineVersionMismatch, "The Target-owned sing-box version does not match the pinned version.");
            case SingBoxEngineStatusKind.Installed:
                return engine.Version!;
            default:
                throw new RuntimeOperationException(RuntimeFailureReason.EngineInvalid, "The Target-owned sing-box engine is invalid.");
        }
    }

    private PreparedRuntimeConfiguration PrepareConfiguration()
    {
        try
        {
            return configurationPreparer.Prepare(profileStore);
        }
        catch (RuntimeConfigurationException exception)
        {
            var reason = exception.Failure switch
            {
                RuntimeConfigurationFailure.ProfileNotSelected => RuntimeFailureReason.ProfileNotSelected,
                RuntimeConfigurationFailure.UnsafeConfiguration or RuntimeConfigurationFailure.NoUsableMixedInbound => RuntimeFailureReason.UnsafeConfiguration,
                _ => RuntimeFailureReason.InvalidConfiguration
            };
            throw new RuntimeOperationException(reason, "The selected profile cannot be prepared for a Host-Safe runtime.");
        }
    }

    private async Task WaitForReadinessAsync(
        ITargetRuntimeProcess process,
        PreparedRuntimeConfiguration configuration,
        CancellationToken cancellationToken)
    {
        var deadline = timeProvider.GetUtcNow() + readinessTimeout;
        while (timeProvider.GetUtcNow() < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (process.HasExited)
            {
                throw new RuntimeOperationException(
                    RuntimeFailureReason.ProcessExitedDuringLaunch,
                    "The runtime exited before becoming ready.");
            }

            if (await readinessProbe.IsListeningAsync(
                    configuration.PrimaryHost,
                    configuration.PrimaryPort,
                    cancellationToken).ConfigureAwait(false))
            {
                return;
            }

            await Task.Delay(pollInterval, timeProvider, cancellationToken).ConfigureAwait(false);
        }

        throw new RuntimeOperationException(RuntimeFailureReason.ReadinessTimedOut, "The runtime did not become ready in time.");
    }

    private async Task CleanupFailedLaunchAsync(
        ITargetRuntimeProcess? launched,
        RuntimeOwnershipRecord? record,
        Guid runtimeConfigurationId)
    {
        var launchedProcessExited = launched is null;
        if (launched is not null)
        {
            try
            {
                if (!launched.HasExited)
                {
                    // This authority is limited to the exact Process.Start result
                    // retained by this launch operation.
                    launched.TerminateForFailedLaunch();
                    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                    await launched.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
                }

                launchedProcessExited = launched.HasExited;
            }
            catch
            {
                try
                {
                    launchedProcessExited = launched.HasExited;
                }
                catch
                {
                    launchedProcessExited = false;
                }
            }
            finally
            {
                if (launchedProcessExited)
                {
                    launched.Dispose();
                }
                else
                {
                    retainedProcess = launched;
                }
            }
        }

        if (!launchedProcessExited)
        {
            return;
        }

        var configurationDeleted = configurationStore.Delete(runtimeConfigurationId);
        if (record is not null && configurationDeleted)
        {
            ownership.ClearFailedLaunchRecord(record);
        }
    }

    private static void ThrowForCheckFailure(BoundedCommandResult check)
    {
        if (check.TimedOut)
        {
            throw new RuntimeOperationException(
                RuntimeFailureReason.ConfigurationCheckTimedOut,
                "The sing-box configuration check timed out.");
        }

        if (check.ExitCode != 0)
        {
            throw new RuntimeOperationException(
                RuntimeFailureReason.ConfigurationCheckFailed,
                "The sing-box configuration check failed.");
        }
    }

    private static WindowsSingBoxRuntimeStatus ToStatus(RuntimeDisposition disposition, string? engineVersion)
    {
        return new WindowsSingBoxRuntimeStatus(
            disposition.Kind,
            engineVersion,
            disposition.Record?.ProfileId,
            disposition.Record?.ProfileRevision,
            disposition.Record?.PrimaryHost,
            disposition.Record?.PrimaryPort);
    }

    private void ReleaseRetainedProcess(int processId)
    {
        if (retainedProcess?.Identity.ProcessId != processId)
        {
            return;
        }

        retainedProcess.Dispose();
        retainedProcess = null;
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
    }
}
