using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Target.Windows.Runtime;

public enum WindowsProcessInspectionKind
{
    NotFound,
    Unreadable,
    Found
}

public sealed record WindowsProcessSnapshot(
    int ProcessId,
    long CreationTimeFileTimeUtc,
    string ExecutablePath,
    string ExecutableSha256);

public sealed record WindowsProcessInspection(
    WindowsProcessInspectionKind Kind,
    WindowsProcessSnapshot? Snapshot)
{
    public static WindowsProcessInspection NotFound { get; } = new(WindowsProcessInspectionKind.NotFound, null);
    public static WindowsProcessInspection Unreadable { get; } = new(WindowsProcessInspectionKind.Unreadable, null);
    public static WindowsProcessInspection Found(WindowsProcessSnapshot snapshot) =>
        new(WindowsProcessInspectionKind.Found, snapshot);
}

public interface IWindowsProcessInspector
{
    WindowsProcessInspection Inspect(int processId);
}

public interface ILoopbackReadinessProbe
{
    Task<bool> IsListeningAsync(string host, int port, CancellationToken cancellationToken);
}

public interface IOwnedProcessTerminator
{
    Task<bool> TerminateAsync(RuntimeOwnershipRecord record, CancellationToken cancellationToken);
}

public sealed class LoopbackTcpReadinessProbe : ILoopbackReadinessProbe
{
    private readonly TimeSpan attemptTimeout;

    public LoopbackTcpReadinessProbe(TimeSpan? attemptTimeout = null)
    {
        this.attemptTimeout = attemptTimeout ?? TimeSpan.FromMilliseconds(250);
    }

    public async Task<bool> IsListeningAsync(string host, int port, CancellationToken cancellationToken)
    {
        if (!string.Equals(host, SingBoxEngineConstants.PrimaryHost, StringComparison.Ordinal)
            || port is < 1 or > ushort.MaxValue)
        {
            return false;
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(attemptTimeout);
        using var client = new TcpClient(AddressFamily.InterNetwork);
        try
        {
            await client.ConnectAsync(IPAddress.Loopback, port, timeout.Token).ConfigureAwait(false);
            return client.Connected;
        }
        catch (Exception exception) when (exception is SocketException or OperationCanceledException)
        {
            return false;
        }
    }
}

public sealed class RuntimeOwnership
{
    private readonly SingBoxEngineLocation engineLocation;
    private readonly RuntimeOwnershipStore recordStore;
    private readonly RuntimeConfigurationStore configurationStore;
    private readonly IWindowsProcessInspector processInspector;
    private readonly ILoopbackReadinessProbe readinessProbe;

    public RuntimeOwnership(
        SingBoxEngineLocation engineLocation,
        RuntimeOwnershipStore recordStore,
        RuntimeConfigurationStore configurationStore,
        IWindowsProcessInspector processInspector,
        ILoopbackReadinessProbe readinessProbe)
    {
        this.engineLocation = engineLocation;
        this.recordStore = recordStore;
        this.configurationStore = configurationStore;
        this.processInspector = processInspector;
        this.readinessProbe = readinessProbe;
    }

    public async Task<RuntimeDisposition> GetDispositionAsync(CancellationToken cancellationToken = default)
    {
        var read = recordStore.Read();
        if (read.Kind == RuntimeOwnershipReadKind.NoRecord)
        {
            return new(RuntimeDispositionKind.NoRecord, null);
        }

        if (read.Kind != RuntimeOwnershipReadKind.ValidRecord || read.Record is null)
        {
            return new(RuntimeDispositionKind.LiveUnproven, null);
        }

        var record = read.Record;
        if (!record.IsValid(engineLocation))
        {
            return new(RuntimeDispositionKind.LiveUnproven, record);
        }

        var inspection = processInspector.Inspect(record.ProcessId);
        if (inspection.Kind == WindowsProcessInspectionKind.NotFound)
        {
            return new(RuntimeDispositionKind.ProcessExited, record);
        }

        if (!MatchesProof(record, inspection))
        {
            return new(RuntimeDispositionKind.LiveUnproven, record);
        }

        if (!configurationStore.ExistsVerified(
                record.RuntimeConfigurationId,
                record.RuntimeConfigurationSha256))
        {
            return new(RuntimeDispositionKind.LiveUnproven, record);
        }

        if (!await readinessProbe.IsListeningAsync(
                record.PrimaryHost,
                record.PrimaryPort,
                cancellationToken).ConfigureAwait(false))
        {
            return new(RuntimeDispositionKind.LiveUnproven, record);
        }

        return new(RuntimeDispositionKind.OwnedRunning, record);
    }

    public async Task<bool> ReproveOwnershipAsync(
        RuntimeOwnershipRecord record,
        CancellationToken cancellationToken)
    {
        var inspection = processInspector.Inspect(record.ProcessId);
        return MatchesProof(record, inspection)
            && configurationStore.ExistsVerified(
                record.RuntimeConfigurationId,
                record.RuntimeConfigurationSha256)
            && await readinessProbe.IsListeningAsync(
                record.PrimaryHost,
                record.PrimaryPort,
                cancellationToken).ConfigureAwait(false);
    }

    public RuntimeOwnershipRecord CreateRecord(
        TargetProcessIdentity identity,
        PreparedRuntimeConfiguration configuration,
        string executableSha256,
        DateTimeOffset recordedStartTimeUtc)
    {
        var record = new RuntimeOwnershipRecord(
            identity.ProcessId,
            identity.CreationTimeFileTimeUtc,
            SingBoxEngineLocation.CanonicalPath(identity.ExecutablePath),
            executableSha256,
            configuration.ProfileId,
            configuration.ProfileRevision,
            configuration.SourceConfigurationSha256,
            configuration.RuntimeConfigurationId,
            configuration.RuntimeConfigurationSha256,
            configuration.PrimaryHost,
            configuration.PrimaryPort,
            recordedStartTimeUtc);
        if (!record.IsValid(engineLocation))
        {
            throw new RuntimeOperationException(RuntimeFailureReason.LaunchFailed, "The launched process identity is invalid.");
        }

        return record;
    }

    public void SaveRecord(RuntimeOwnershipRecord record) => recordStore.Save(record);

    public bool ClearExitedRecord(RuntimeOwnershipRecord record)
    {
        if (!record.IsValid(engineLocation))
        {
            return false;
        }

        if (processInspector.Inspect(record.ProcessId).Kind != WindowsProcessInspectionKind.NotFound)
        {
            return false;
        }

        if (!configurationStore.Delete(record.RuntimeConfigurationId))
        {
            return false;
        }

        if (!recordStore.ClearIfMatches(record))
        {
            return false;
        }
        return true;
    }

    public bool ClearFailedLaunchRecord(RuntimeOwnershipRecord record)
    {
        return recordStore.ClearIfMatches(record);
    }

    private bool MatchesProof(RuntimeOwnershipRecord record, WindowsProcessInspection inspection)
    {
        try
        {
            if (!record.IsValid(engineLocation)
                || inspection.Kind != WindowsProcessInspectionKind.Found
                || inspection.Snapshot is not { } snapshot)
            {
                return false;
            }

            return snapshot.ProcessId == record.ProcessId
                && snapshot.CreationTimeFileTimeUtc == record.ProcessCreationTimeFileTimeUtc
                && string.Equals(
                    SingBoxEngineLocation.CanonicalPath(snapshot.ExecutablePath),
                    engineLocation.ExecutablePath,
                    StringComparison.OrdinalIgnoreCase)
                && string.Equals(
                    SingBoxEngineLocation.CanonicalPath(record.ExecutablePath),
                    engineLocation.ExecutablePath,
                    StringComparison.OrdinalIgnoreCase)
                && string.Equals(snapshot.ExecutableSha256, record.ExecutableSha256, StringComparison.Ordinal);
        }
        catch
        {
            return false;
        }
    }
}

public sealed class WindowsProcessInspector : IWindowsProcessInspector
{
    private const int ErrorInvalidParameter = 87;
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint Synchronize = 0x00100000;
    private const uint WaitObject0 = 0x00000000;
    private const uint WaitFailed = 0xFFFFFFFF;

    public WindowsProcessInspection Inspect(int processId)
    {
        if (processId <= 0)
        {
            return WindowsProcessInspection.Unreadable;
        }

        using var handle = NativeMethods.OpenProcess(ProcessQueryLimitedInformation | Synchronize, false, processId);
        if (handle.IsInvalid)
        {
            return Marshal.GetLastWin32Error() == ErrorInvalidParameter
                ? WindowsProcessInspection.NotFound
                : WindowsProcessInspection.Unreadable;
        }

        var waitResult = NativeMethods.WaitForSingleObject(handle, 0);
        if (waitResult == WaitObject0)
        {
            return WindowsProcessInspection.NotFound;
        }

        if (waitResult == WaitFailed)
        {
            return WindowsProcessInspection.Unreadable;
        }

        try
        {
            var identity = ReadIdentity(handle, processId);
            var hash = SingBoxEngineDiscovery.Sha256(identity.ExecutablePath);
            return WindowsProcessInspection.Found(new WindowsProcessSnapshot(
                identity.ProcessId,
                identity.CreationTimeFileTimeUtc,
                identity.ExecutablePath,
                hash));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or Win32Exception)
        {
            return WindowsProcessInspection.Unreadable;
        }
    }

    internal static TargetProcessIdentity ReadIdentity(System.Diagnostics.Process process)
    {
        ArgumentNullException.ThrowIfNull(process);
        return ReadIdentity(process.SafeHandle, process.Id);
    }

    internal static TargetProcessIdentity ReadIdentity(SafeProcessHandle handle, int processId)
    {
        if (!NativeMethods.GetProcessTimes(handle, out var creation, out _, out _, out _))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        var capacity = 32_768;
        var buffer = new char[capacity];
        if (!NativeMethods.QueryFullProcessImageName(handle, 0, buffer, ref capacity))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        var path = SingBoxEngineLocation.CanonicalPath(new string(buffer, 0, capacity));
        return new TargetProcessIdentity(processId, creation.ToLong(), path);
    }

    private static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern SafeProcessHandle OpenProcess(
            uint desiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
            int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetProcessTimes(
            SafeProcessHandle process,
            out FileTime creationTime,
            out FileTime exitTime,
            out FileTime kernelTime,
            out FileTime userTime);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool QueryFullProcessImageName(
            SafeProcessHandle process,
            uint flags,
            [Out] char[] executableName,
            ref int size);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint WaitForSingleObject(SafeProcessHandle handle, uint milliseconds);
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FileTime
    {
        public uint Low;
        public uint High;

        public readonly long ToLong() => unchecked((long)(((ulong)High << 32) | Low));
    }
}

public sealed class WindowsOwnedProcessTerminator : IOwnedProcessTerminator
{
    private const uint ProcessTerminate = 0x0001;
    private const uint Synchronize = 0x00100000;
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint WaitObject0 = 0x00000000;
    private readonly SingBoxEngineLocation engineLocation;
    private readonly TimeSpan stopTimeout;

    public WindowsOwnedProcessTerminator(
        SingBoxEngineLocation engineLocation,
        TimeSpan? stopTimeout = null)
    {
        this.engineLocation = engineLocation;
        this.stopTimeout = stopTimeout ?? TimeSpan.FromSeconds(5);
    }

    public Task<bool> TerminateAsync(RuntimeOwnershipRecord record, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!record.IsValid(engineLocation))
        {
            return Task.FromResult(false);
        }

        using var handle = NativeMethods.OpenProcess(
            ProcessTerminate | Synchronize | ProcessQueryLimitedInformation,
            false,
            record.ProcessId);
        if (handle.IsInvalid)
        {
            return Task.FromResult(false);
        }

        try
        {
            var identity = WindowsProcessInspector.ReadIdentity(handle, record.ProcessId);
            var executableHash = SingBoxEngineDiscovery.Sha256(identity.ExecutablePath);
            if (identity.CreationTimeFileTimeUtc != record.ProcessCreationTimeFileTimeUtc
                || !string.Equals(identity.ExecutablePath, engineLocation.ExecutablePath, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(identity.ExecutablePath, record.ExecutablePath, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(executableHash, record.ExecutableSha256, StringComparison.Ordinal))
            {
                return Task.FromResult(false);
            }

            if (!NativeMethods.TerminateProcess(handle, 0))
            {
                return Task.FromResult(false);
            }

            var milliseconds = (uint)Math.Clamp(stopTimeout.TotalMilliseconds, 1, 30_000);
            return Task.FromResult(NativeMethods.WaitForSingleObject(handle, milliseconds) == WaitObject0);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or Win32Exception)
        {
            return Task.FromResult(false);
        }
    }

    private static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern SafeProcessHandle OpenProcess(
            uint desiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
            int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint WaitForSingleObject(SafeProcessHandle handle, uint milliseconds);
    }
}
