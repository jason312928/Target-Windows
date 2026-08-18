namespace Target.Windows.Core;

public interface IProfileFileWriter
{
    void WriteAtomically(string path, ReadOnlySpan<byte> content);
}

public sealed class DurableProfileFileWriter : IProfileFileWriter
{
    public void WriteAtomically(string path, ReadOnlySpan<byte> content)
    {
        var directory = Path.GetDirectoryName(path)
            ?? throw new ProfileStorageException(ProfileStorageError.PersistenceFailure, "The storage path is invalid.");
        Directory.CreateDirectory(directory);

        var temporaryPath = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 4096,
                FileOptions.WriteThrough))
            {
                stream.Write(content);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporaryPath, path, overwrite: true);
        }
        catch (ProfileStorageException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new ProfileStorageException(
                ProfileStorageError.PersistenceFailure,
                "The encrypted profile record could not be persisted.",
                exception);
        }
        finally
        {
            try
            {
                File.Delete(temporaryPath);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }
}
