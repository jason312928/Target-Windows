namespace Target.Windows.Runtime;

internal sealed class RuntimeLifecycleLock
{
    private readonly string root;
    private readonly string path;
    private readonly TimeSpan timeout;

    public RuntimeLifecycleLock(SingBoxEngineLocation engineLocation, TimeSpan? timeout = null)
    {
        root = engineLocation.IsTestOverride
            ? Path.GetDirectoryName(engineLocation.ExecutablePath)
                ?? throw new ArgumentException("The test engine path is invalid.", nameof(engineLocation))
            : SingBoxEngineLocation.GetProductionRoot();
        root = SingBoxEngineLocation.CanonicalPath(root);
        path = SingBoxEngineLocation.CanonicalPath(Path.Combine(root, "runtime.lifecycle.lock"));
        this.timeout = timeout ?? TimeSpan.FromSeconds(10);
    }

    public async Task<FileStream> AcquireAsync(CancellationToken cancellationToken)
    {
        RuntimePathSecurity.EnsurePrivateDirectory(root);
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return new FileStream(
                    path,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    1,
                    FileOptions.WriteThrough);
            }
            catch (IOException) when (DateTimeOffset.UtcNow < deadline)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(50), cancellationToken).ConfigureAwait(false);
            }
            catch (IOException exception)
            {
                throw new RuntimeOperationException(
                    RuntimeFailureReason.InvalidLifecycle,
                    "Another Target process is changing the runtime lifecycle.",
                    exception);
            }
            catch (UnauthorizedAccessException exception)
            {
                throw new RuntimeOperationException(
                    RuntimeFailureReason.StorageFailure,
                    "The runtime lifecycle lock is unavailable.",
                    exception);
            }

            if (DateTimeOffset.UtcNow >= deadline)
            {
                throw new RuntimeOperationException(
                    RuntimeFailureReason.InvalidLifecycle,
                    "Another Target process is changing the runtime lifecycle.");
            }
        }
    }
}
