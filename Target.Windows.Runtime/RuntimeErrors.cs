namespace Target.Windows.Runtime;

public enum SingBoxEngineStatusKind
{
    NotInstalled,
    Invalid,
    Installed
}

public sealed record SingBoxEngineStatus(SingBoxEngineStatusKind Kind, string? Version)
{
    public static SingBoxEngineStatus NotInstalled { get; } = new(SingBoxEngineStatusKind.NotInstalled, null);
    public static SingBoxEngineStatus Invalid { get; } = new(SingBoxEngineStatusKind.Invalid, null);

    public static SingBoxEngineStatus Installed(string version) =>
        new(SingBoxEngineStatusKind.Installed, version);
}

public enum RuntimeDispositionKind
{
    NoRecord,
    OwnedRunning,
    ProcessExited,
    LiveUnproven
}

public sealed record RuntimeDisposition(RuntimeDispositionKind Kind, RuntimeOwnershipRecord? Record);

public enum RuntimeFailureReason
{
    EngineNotInstalled,
    EngineInvalid,
    EngineVersionMismatch,
    ProfileNotSelected,
    InvalidConfiguration,
    UnsafeConfiguration,
    ConfigurationCheckFailed,
    ConfigurationCheckTimedOut,
    DuplicateRuntime,
    LiveRuntimeUnproven,
    InvalidLifecycle,
    LaunchFailed,
    ReadinessTimedOut,
    ProcessExitedDuringLaunch,
    StopFailed,
    Cancellation,
    StorageFailure
}

public sealed class RuntimeOperationException : Exception
{
    public RuntimeOperationException(RuntimeFailureReason reason, string message)
        : base(message)
    {
        Reason = reason;
    }

    public RuntimeOperationException(RuntimeFailureReason reason, string message, Exception innerException)
        : base(message, innerException)
    {
        Reason = reason;
    }

    public RuntimeFailureReason Reason { get; }
}

public enum RuntimeConfigurationFailure
{
    InvalidJson,
    UnsafeConfiguration,
    NoUsableMixedInbound,
    PortUnavailable,
    ProfileNotSelected,
    SourceTooLarge
}

public sealed class RuntimeConfigurationException : Exception
{
    public RuntimeConfigurationException(RuntimeConfigurationFailure failure, string message)
        : base(message)
    {
        Failure = failure;
    }

    public RuntimeConfigurationFailure Failure { get; }
}
