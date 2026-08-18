namespace Target.Windows.Core;

public enum ProfileStorageError
{
    InvalidProfileName,
    ProfileNotFound,
    InvalidStoredMetadata,
    ProtectedKeyMissing,
    ProtectedKeyInvalid,
    InvalidEncryptedEnvelope,
    UnsupportedStorageVersion,
    AadBindingMismatch,
    AuthenticationFailure,
    MixedOrDowngradedStorage,
    PersistenceFailure
}

public sealed class ProfileStorageException : Exception
{
    public ProfileStorageException(ProfileStorageError error, string message)
        : base(message)
    {
        Error = error;
    }

    public ProfileStorageException(ProfileStorageError error, string message, Exception innerException)
        : base(message, innerException)
    {
        Error = error;
    }

    public ProfileStorageError Error { get; }
}
