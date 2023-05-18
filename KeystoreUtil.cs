using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls.Crypto.Impl;
using Org.BouncyCastle.Utilities;
using Serilog;
using System.Diagnostics;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SecureRepository;

internal class KeystoreUtil
{
    internal static string keystorePath = Path.Combine(Registration.resources, "keystore/");
    internal static string masterPath = Path.Combine(Registration.resources, "master/");

    private static readonly string keystorePassword = "sigurnost";
    internal static string wslStart = "wsl.exe";

    internal static string hmacPassword = "sigurnost";

    internal static void CreateKeystore(string username, string password)
    {
        string masterKeyFile = $"{Path.Combine(masterPath, username)}_master.key";

        X509Certificate2 rootCert;
        X509Certificate2 clientCert;
        try
        {
            rootCert = new(Path.Combine(Registration.caPath,
                $"rootca.pem"));
        }
        catch (Exception e)
        {
            Log.Logger.Fatal(e.Message, e.StackTrace);
            throw;
        }
        try
        {
            clientCert = new(Path.Combine(Registration.certsPath,
                $"{username}.pem"));
        }
        catch (Exception e)
        {
            Console.WriteLine("Your certificate is missing.");
            Log.Logger.Error(e.Message, e.StackTrace);
            throw;
        }
        RSA userPublicKey = clientCert.GetRSAPublicKey();
        RSA rootPublicKey = rootCert.GetRSAPublicKey();

        var aesObject = Aes.Create();
        aesObject.KeySize = 256;
        aesObject.GenerateKey();
        var masterKey = aesObject.Key;

        byte[] encryptedByUser;
        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
        {
            rsa.ImportParameters(userPublicKey.ExportParameters(false));
            encryptedByUser = rsa.Encrypt(masterKey, true);
        }

        byte[] encryptedByBoth = null;
        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
        {
            rsa.ImportParameters(rootPublicKey.ExportParameters(false));
            encryptedByBoth = rsa.Encrypt(encryptedByUser, true);
        }
        if (encryptedByBoth != null)
            File.WriteAllBytes(masterKeyFile, encryptedByBoth);
        else
            throw new Exception("Couldn't create master key.");
    }

    internal static void EncryptAesGcm(string file, byte[] key, byte[] data)
    {
        byte[] nonce = new byte[12];
        new SecureRandom().NextBytes(nonce);

        IBufferedCipher cipher = CipherUtilities.GetCipher("AES/GCM/NOPADDING");
        cipher.Init(true, new AeadParameters(new KeyParameter(key), 128, nonce));

        byte[] encryptedData = cipher.DoFinal(data);

        byte[] encryptedDataPlusNonce = new byte[nonce.Length + encryptedData.Length];
        Array.Copy(nonce, 0, encryptedDataPlusNonce, 0, nonce.Length);
        Array.Copy(encryptedData, 0, encryptedDataPlusNonce, nonce.Length, encryptedData.Length);

        File.WriteAllBytes(file, encryptedDataPlusNonce);
    }

    internal static byte[] DecryptAesGcm(string file, byte[] key)
    {
        if (!HmacUtil.VerifyHmacForFile(file, key))
        {
            Log.Logger.Error($"Invalid HMAC for file {file}");
            Console.WriteLine($"Invalid HMAC for file {file}. It has been tampered with.");
        }

        byte[] encryptedDataPlusNonce = HmacUtil.SkipHmac(file, false); ;

        byte[] nonce = new byte[12];
        Array.Copy(encryptedDataPlusNonce, 0, nonce, 0, 12);

        byte[] encryptedData = new byte[encryptedDataPlusNonce.Length - 12];
        Array.Copy(encryptedDataPlusNonce, 12, encryptedData, 0, encryptedData.Length);

        IBufferedCipher cipher = CipherUtilities.GetCipher("AES/GCM/NOPADDING");
        cipher.Init(false, new AeadParameters(new KeyParameter(key), 128, nonce));

        byte[] decryptedData = cipher.DoFinal(encryptedData);

        return decryptedData;
    }

    internal static void Store(string alias, byte[] key, byte[] master)
    {
        var keyFilePath = Path.Combine(keystorePath, $"{alias}.key");
        EncryptAesGcm(keyFilePath, master, key);
        HmacUtil.GenerateHmacForFile(keyFilePath, master);
    }

    internal static byte[] Retrieve(string alias, byte[] master)
    {
        var keyFilePath = Path.Combine(keystorePath, $"{alias}.key");
        return DecryptAesGcm(keyFilePath, master);
    }

    internal static string GetAlias(string username, string file)
    {
        return Path.Combine($"{username}/", file).Replace('\\', '_').Replace('/', '_');
    }

    internal static byte[] GetMaster(string username, string passphrase)
    {
        string masterKeyFile = $"{Path.Combine(masterPath, username)}_master.key";
        var encryptedWithBoth = File.ReadAllBytes(masterKeyFile);

        string userKeyFilePath = Path.Combine(Registration.privatePath, $"{username}.key");
        
        var userKey = Authentication.LoadPrivateKey(userKeyFilePath, passphrase);
        var rootCaKey = Authentication.LoadPrivateKey(Path.Combine(Registration.privatePath,
                "private4096.key"), keystorePassword);

        byte[] encryptedWithUser;
        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
        {
            rsa.ImportParameters(DotNetUtilities.ToRSAParameters(rootCaKey));
            encryptedWithUser = rsa.Decrypt(encryptedWithBoth, true);
        }

        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
        {
            rsa.ImportParameters(DotNetUtilities.ToRSAParameters(userKey));
            return rsa.Decrypt(encryptedWithUser, true);
        }
    }
}