using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Target.Windows.Runtime;

public static class SingBoxEngineConstants
{
    public const string PinnedVersion = "1.13.16";
    public const string PrimaryHost = "127.0.0.1";
}

public sealed record SingBoxEngineLocation
{
    private SingBoxEngineLocation(string executablePath, bool isTestOverride)
    {
        ExecutablePath = CanonicalPath(executablePath);
        IsTestOverride = isTestOverride;
    }

    public string ExecutablePath { get; }
    public bool IsTestOverride { get; }

    public static SingBoxEngineLocation Production() =>
        new(GetProductionExecutablePath(), false);

    public static SingBoxEngineLocation ForTesting(string executablePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        return new(executablePath, true);
    }

    public static string GetProductionRoot()
    {
        var localApplicationData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(localApplicationData))
        {
            throw new InvalidOperationException("The per-user local application data directory is unavailable.");
        }

        return Path.Combine(localApplicationData, "Target", "sing-box");
    }

    public static string GetProductionExecutablePath() =>
        Path.Combine(GetProductionRoot(), "bin", "sing-box.exe");

    public static string GetProductionRuntimeRoot() =>
        Path.Combine(GetProductionRoot(), "runtime");

    internal static string CanonicalPath(string path)
    {
        var fullPath = Path.GetFullPath(path);
        return fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }
}

public sealed record BoundedCommandResult(
    int ExitCode,
    string StandardOutput,
    string StandardError,
    bool TimedOut)
{
    public bool Succeeded => !TimedOut && ExitCode == 0;
}

public interface ISingBoxCommandExecutor
{
    Task<BoundedCommandResult> VersionAsync(CancellationToken cancellationToken);
    Task<BoundedCommandResult> CheckAsync(string runtimeConfigurationPath, CancellationToken cancellationToken);
}

public interface ISingBoxProcessLauncher
{
    ITargetRuntimeProcess LaunchRun(string runtimeConfigurationPath);
}

public interface ITargetRuntimeProcess : IDisposable
{
    TargetProcessIdentity Identity { get; }
    bool HasExited { get; }
    Task WaitForExitAsync(CancellationToken cancellationToken);
    void TerminateForFailedLaunch();
}

public sealed record TargetProcessIdentity(
    int ProcessId,
    long CreationTimeFileTimeUtc,
    string ExecutablePath);

public sealed class WindowsSingBoxCommandExecutor : ISingBoxCommandExecutor, ISingBoxProcessLauncher
{
    private const int MaximumOutputBytes = 64 * 1024;
    private readonly SingBoxEngineLocation location;
    private readonly TimeSpan commandTimeout;

    public WindowsSingBoxCommandExecutor(
        SingBoxEngineLocation? location = null,
        TimeSpan? commandTimeout = null)
    {
        this.location = location ?? SingBoxEngineLocation.Production();
        this.commandTimeout = commandTimeout ?? TimeSpan.FromSeconds(15);
        if (this.commandTimeout <= TimeSpan.Zero || this.commandTimeout > TimeSpan.FromMinutes(2))
        {
            throw new ArgumentOutOfRangeException(nameof(commandTimeout));
        }
    }

    public Task<BoundedCommandResult> VersionAsync(CancellationToken cancellationToken) =>
        RunBoundedAsync(["version"], cancellationToken);

    public Task<BoundedCommandResult> CheckAsync(
        string runtimeConfigurationPath,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runtimeConfigurationPath);
        return RunBoundedAsync(["check", "-c", runtimeConfigurationPath], cancellationToken);
    }

    public ITargetRuntimeProcess LaunchRun(string runtimeConfigurationPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runtimeConfigurationPath);
        var startInfo = CreateStartInfo(["run", "-c", runtimeConfigurationPath]);
        startInfo.RedirectStandardOutput = false;
        startInfo.RedirectStandardError = false;
        startInfo.StandardOutputEncoding = null;
        startInfo.StandardErrorEncoding = null;
        var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("The sing-box process could not be started.");
        try
        {
            var identity = WindowsProcessInspector.ReadIdentity(process);
            return new WindowsTargetRuntimeProcess(process, identity);
        }
        catch
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: false);
                }
            }
            catch
            {
            }

            process.Dispose();
            throw;
        }
    }

    private async Task<BoundedCommandResult> RunBoundedAsync(
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        var startInfo = CreateStartInfo(arguments);
        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("The sing-box command could not be started.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(commandTimeout);

        var standardOutput = ReadBoundedAsync(process.StandardOutput.BaseStream, MaximumOutputBytes, timeout.Token);
        var standardError = ReadBoundedAsync(process.StandardError.BaseStream, MaximumOutputBytes, timeout.Token);
        var timedOut = false;
        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            timedOut = true;
            TryTerminate(process);
        }

        if (cancellationToken.IsCancellationRequested)
        {
            TryTerminate(process);
            throw new OperationCanceledException(cancellationToken);
        }

        var output = await standardOutput.ConfigureAwait(false);
        var error = await standardError.ConfigureAwait(false);
        return new BoundedCommandResult(
            timedOut ? -1 : process.ExitCode,
            output,
            error,
            timedOut);
    }

    private ProcessStartInfo CreateStartInfo(IReadOnlyList<string> arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = location.ExecutablePath,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(location.ExecutablePath) ?? Environment.CurrentDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        return startInfo;
    }

    private static async Task<string> ReadBoundedAsync(
        Stream stream,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[4096];
        using var output = new MemoryStream(Math.Min(maximumBytes, 16 * 1024));
        try
        {
            while (true)
            {
                var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                var remaining = maximumBytes - (int)output.Length;
                if (remaining > 0)
                {
                    output.Write(buffer, 0, Math.Min(read, remaining));
                }
            }
        }
        catch (OperationCanceledException)
        {
        }

        return Encoding.UTF8.GetString(output.GetBuffer(), 0, (int)output.Length);
    }

    private static void TryTerminate(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: false);
            }
        }
        catch
        {
        }
    }
}

public sealed class WindowsTargetRuntimeProcess(Process process, TargetProcessIdentity identity) : ITargetRuntimeProcess
{
    private readonly Process process = process;

    public TargetProcessIdentity Identity { get; } = identity;
    public bool HasExited => process.HasExited;

    public Task WaitForExitAsync(CancellationToken cancellationToken) =>
        process.WaitForExitAsync(cancellationToken);

    public void TerminateForFailedLaunch()
    {
        if (!process.HasExited)
        {
            process.Kill(entireProcessTree: false);
        }
    }

    public void Dispose() => process.Dispose();
}

public sealed class SingBoxEngineDiscovery
{
    private static readonly Regex VersionPattern = new(
        @"^sing-box version (?<version>\d+\.\d+\.\d+)(?:\s|$)",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private readonly SingBoxEngineLocation location;
    private readonly ISingBoxCommandExecutor commands;

    public SingBoxEngineDiscovery(
        SingBoxEngineLocation? location = null,
        ISingBoxCommandExecutor? commands = null)
    {
        this.location = location ?? SingBoxEngineLocation.Production();
        this.commands = commands ?? new WindowsSingBoxCommandExecutor(this.location);
    }

    public string ExecutablePath => location.ExecutablePath;

    public async Task<SingBoxEngineStatus> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        if (!File.Exists(location.ExecutablePath))
        {
            return SingBoxEngineStatus.NotInstalled;
        }

        try
        {
            if (File.GetAttributes(location.ExecutablePath).HasFlag(FileAttributes.ReparsePoint))
            {
                return SingBoxEngineStatus.Invalid;
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return SingBoxEngineStatus.Invalid;
        }

        BoundedCommandResult result;
        try
        {
            result = await commands.VersionAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return SingBoxEngineStatus.Invalid;
        }

        if (!result.Succeeded)
        {
            return SingBoxEngineStatus.Invalid;
        }

        var firstLine = result.StandardOutput
            .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .FirstOrDefault();
        var match = firstLine is null ? null : VersionPattern.Match(firstLine.Trim());
        return match is { Success: true }
            ? SingBoxEngineStatus.Installed(match.Groups["version"].Value)
            : SingBoxEngineStatus.Invalid;
    }

    public static string Sha256(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }
}
