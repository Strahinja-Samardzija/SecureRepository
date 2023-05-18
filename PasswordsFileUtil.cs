using Org.BouncyCastle.Crypto.Generators;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Resources;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SecureRepository;
internal class PasswordsFileUtil
{
    internal static string passwordsFile = Path.Combine(Registration.resources,
        "passwords.txt");

    static string passwordsPassword = "sigurnost";

    internal static void AddPassword(string username, string password)
    {
        if (!HmacUtil.VerifyHmacForFile(passwordsFile, passwordsPassword))
        {
            Log.Logger.Error("passwords.txt has been tempered with");
            throw new SecurityException("Invalid HMAC");
        }

        HmacUtil.RemoveHmac(passwordsFile, true);
        
        using (StreamWriter writer = new StreamWriter(passwordsFile, true))
        {
            writer.WriteLine($"{username},{BcryptHash(password)}");
        }

        HmacUtil.GenerateHmacForFile(passwordsFile, passwordsPassword);
    }

    internal static bool UniqueUsernameCheck(string username)
    {
        if (!HmacUtil.VerifyHmacForFile(passwordsFile, passwordsPassword))
        {
            Log.Logger.Error("passwords.txt has been tempered with");
            throw new SecurityException("Invalid HMAC");
        }

        string[] lines = File.ReadAllLines(passwordsFile);
        foreach (string line in lines)
        {
            string[] parts = line.Split(',');
            if (parts[0] == username)
            {
                return false;
            }
        }
        return true;
    }

    internal static bool CheckPassword(string username, string password)
    {
        if (!HmacUtil.VerifyHmacForFile(passwordsFile, passwordsPassword))
        {
            Log.Logger.Error("passwords.txt has been tempered with");
            throw new SecurityException("Invalid HMAC");
        }

        var passwords = File.ReadAllLines(passwordsFile);
        var passwordLine = passwords.FirstOrDefault(line => line.StartsWith(username + ","));
        if (passwordLine == null) return false;

        var parts = passwordLine.Split(',');
        var hash = parts[1];

        return OpenBsdBCrypt.CheckPassword(hash, password.ToCharArray());
    }

    static string BcryptHash(string password)
    {
        byte[] salt = new byte[16];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }

        return OpenBsdBCrypt.Generate(password.ToCharArray(), salt, 12);
    }
}
