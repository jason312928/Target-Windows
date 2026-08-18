namespace Target.Windows.Core;

public static class ProfileStoragePaths
{
    public static string GetDefaultProfileRoot()
    {
        var localApplicationData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return Path.Combine(localApplicationData, "Target", "Profiles");
    }

    public static string GetDefaultProtectedKeyPath()
    {
        var localApplicationData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return Path.Combine(localApplicationData, "Target", "Secrets", "profile-master-key-v1.dpapi");
    }
}
