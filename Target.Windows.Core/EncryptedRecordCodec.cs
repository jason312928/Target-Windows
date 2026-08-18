using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Target.Windows.Core;

internal static class EncryptedRecordCodec
{
    internal const int FormatVersion = 1;
    private const int VersionSize = sizeof(int);
    private const int DigestSize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private static readonly byte[] Magic = "TWPRFENC"u8.ToArray();
    private static readonly int HeaderSize = Magic.Length + VersionSize + DigestSize + NonceSize + TagSize;

    public static byte[] Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, string kind, string logicalPath)
    {
        ValidateKey(key);
        var aad = CreateAad(kind, logicalPath);
        var bindingDigest = SHA256.HashData(aad);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];

        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);

            var envelope = new byte[HeaderSize + ciphertext.Length];
            var offset = 0;
            Magic.CopyTo(envelope, offset);
            offset += Magic.Length;
            BinaryPrimitives.WriteInt32LittleEndian(envelope.AsSpan(offset, VersionSize), FormatVersion);
            offset += VersionSize;
            bindingDigest.CopyTo(envelope, offset);
            offset += DigestSize;
            nonce.CopyTo(envelope, offset);
            offset += NonceSize;
            tag.CopyTo(envelope, offset);
            offset += TagSize;
            ciphertext.CopyTo(envelope, offset);
            return envelope;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aad);
            CryptographicOperations.ZeroMemory(bindingDigest);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    public static byte[] Decrypt(ReadOnlySpan<byte> envelope, ReadOnlySpan<byte> key, string kind, string logicalPath)
    {
        ValidateKey(key);
        if (LooksLikePlaintext(envelope))
        {
            throw new ProfileStorageException(
                ProfileStorageError.MixedOrDowngradedStorage,
                "A plaintext or downgraded profile record was found.");
        }

        if (envelope.Length < HeaderSize || !envelope[..Magic.Length].SequenceEqual(Magic))
        {
            throw new ProfileStorageException(
                ProfileStorageError.InvalidEncryptedEnvelope,
                "An encrypted profile record has an invalid envelope.");
        }

        var offset = Magic.Length;
        var version = BinaryPrimitives.ReadInt32LittleEndian(envelope.Slice(offset, VersionSize));
        offset += VersionSize;
        if (version != FormatVersion)
        {
            throw new ProfileStorageException(
                ProfileStorageError.UnsupportedStorageVersion,
                "The encrypted profile record version is unsupported.");
        }

        var storedDigest = envelope.Slice(offset, DigestSize);
        offset += DigestSize;
        var nonce = envelope.Slice(offset, NonceSize);
        offset += NonceSize;
        var tag = envelope.Slice(offset, TagSize);
        offset += TagSize;
        var ciphertext = envelope[offset..];

        var aad = CreateAad(kind, logicalPath);
        var expectedDigest = SHA256.HashData(aad);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(storedDigest, expectedDigest))
            {
                throw new ProfileStorageException(
                    ProfileStorageError.AadBindingMismatch,
                    "The encrypted profile record binding is invalid.");
            }

            var plaintext = new byte[ciphertext.Length];
            try
            {
                using var aes = new AesGcm(key, TagSize);
                aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);
                return plaintext;
            }
            catch (AuthenticationTagMismatchException exception)
            {
                CryptographicOperations.ZeroMemory(plaintext);
                throw new ProfileStorageException(
                    ProfileStorageError.AuthenticationFailure,
                    "Encrypted profile record authentication failed.",
                    exception);
            }
            catch (CryptographicException exception)
            {
                CryptographicOperations.ZeroMemory(plaintext);
                throw new ProfileStorageException(
                    ProfileStorageError.AuthenticationFailure,
                    "Encrypted profile record authentication failed.",
                    exception);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aad);
            CryptographicOperations.ZeroMemory(expectedDigest);
        }
    }

    private static byte[] CreateAad(string kind, string logicalPath) => Encoding.UTF8.GetBytes(
        $"Target.Windows.ProfileStorage|version={FormatVersion}|kind={kind}|path={logicalPath}");

    private static bool LooksLikePlaintext(ReadOnlySpan<byte> content)
    {
        foreach (var value in content)
        {
            if (value is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n')
            {
                continue;
            }

            return value is (byte)'{' or (byte)'[' or (byte)'\"';
        }

        return false;
    }

    private static void ValidateKey(ReadOnlySpan<byte> key)
    {
        if (key.Length != 32)
        {
            throw new ProfileStorageException(
                ProfileStorageError.ProtectedKeyInvalid,
                "The profile encryption key is invalid.");
        }
    }
}
