using System.Security.Cryptography;

namespace Target.Windows.Core;

public sealed class DpapiProfileEncryptionKeyProvider : IProfileEncryptionKeyProvider
{
    private const int KeySize = 32;
    private readonly string keyPath;
    private readonly IProfileFileWriter fileWriter;

    public DpapiProfileEncryptionKeyProvider(string keyPath, IProfileFileWriter? fileWriter = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyPath);
        this.keyPath = Path.GetFullPath(keyPath);
        this.fileWriter = fileWriter ?? new DurableProfileFileWriter();
    }

    public byte[] GetKey(ProfileKeyAccess access)
    {
        if (File.Exists(keyPath))
        {
            return UnprotectExistingKey();
        }

        if (access == ProfileKeyAccess.OpenExistingStore)
        {
            throw new ProfileStorageException(
                ProfileStorageError.ProtectedKeyMissing,
                "The protected profile encryption key is missing.");
        }

        return CreateProtectedKey();
    }

    private byte[] CreateProtectedKey()
    {
        var key = RandomNumberGenerator.GetBytes(KeySize);
        byte[]? protectedKey = null;
        try
        {
            protectedKey = ProtectedData.Protect(key, optionalEntropy: null, DataProtectionScope.CurrentUser);
            fileWriter.WriteAtomically(keyPath, protectedKey);
            return key;
        }
        catch (ProfileStorageException)
        {
            CryptographicOperations.ZeroMemory(key);
            throw;
        }
        catch (Exception exception) when (exception is CryptographicException or PlatformNotSupportedException)
        {
            CryptographicOperations.ZeroMemory(key);
            throw new ProfileStorageException(
                ProfileStorageError.ProtectedKeyInvalid,
                "The profile encryption key could not be protected.",
                exception);
        }
        finally
        {
            if (protectedKey is not null)
            {
                CryptographicOperations.ZeroMemory(protectedKey);
            }
        }
    }

    private byte[] UnprotectExistingKey()
    {
        byte[] protectedKey;
        try
        {
            protectedKey = File.ReadAllBytes(keyPath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new ProfileStorageException(
                ProfileStorageError.ProtectedKeyInvalid,
                "The protected profile encryption key could not be read.",
                exception);
        }

        byte[]? key = null;
        try
        {
            key = ProtectedData.Unprotect(protectedKey, optionalEntropy: null, DataProtectionScope.CurrentUser);
            if (key.Length != KeySize)
            {
                CryptographicOperations.ZeroMemory(key);
                key = null;
                throw new ProfileStorageException(
                    ProfileStorageError.ProtectedKeyInvalid,
                    "The protected profile encryption key is invalid.");
            }

            return key;
        }
        catch (ProfileStorageException)
        {
            throw;
        }
        catch (Exception exception) when (exception is CryptographicException or PlatformNotSupportedException)
        {
            if (key is not null)
            {
                CryptographicOperations.ZeroMemory(key);
            }

            throw new ProfileStorageException(
                ProfileStorageError.ProtectedKeyInvalid,
                "The protected profile encryption key could not be decrypted.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedKey);
        }
    }
}
