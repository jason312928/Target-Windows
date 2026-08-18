namespace Target.Windows.Core;

public enum ProfileKeyAccess
{
    InitializeNewStore,
    OpenExistingStore
}

public interface IProfileEncryptionKeyProvider
{
    byte[] GetKey(ProfileKeyAccess access);
}
