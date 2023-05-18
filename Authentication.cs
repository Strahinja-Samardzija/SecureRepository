using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using System.Reflection.Metadata.Ecma335;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using static Org.BouncyCastle.Crypto.Engines.SM2Engine;
using System.Diagnostics.Metrics;
using Org.BouncyCastle.Pkix;
using Serilog;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;

namespace SecureRepository;

internal class Authentication
{
    static string rootCaCertFile = Path.Combine(Registration.caPath, "rootca.pem");
    internal static string crlFile = Path.Combine(Registration.caPath, "crl/crl.pem");

    internal string Username { get; private set; } = null;

    internal bool Login()
    {
        Console.Write("Enter your username: ");
        var username = Console.ReadLine();

        if (PasswordsFileUtil.UniqueUsernameCheck(username))
        {
            Console.WriteLine("You need to register first.");
            return false;
        }

        try
        {
            using (X509Certificate2 rootCert = new(rootCaCertFile))
            {
                using (X509Certificate2 clientCert = new(Path.Combine(Registration.certsPath,
                    $"{username}.pem")))
                {

                    if (!IsCertificateTrusted(clientCert, rootCert))
                    {
                        return false;
                    }

                    var nonce = GenerateNonce();
                    var signature = UserSignedNonce(nonce, username);

                    RSA publicKey = clientCert.GetRSAPublicKey();
                    bool verified = publicKey.VerifyData(nonce, signature,
                        HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                    if (!verified)
                    {
                        Console.WriteLine("You might not be the owner of the certificate.");
                        return false;
                    }
                }
            }
        }
        catch (Exception e)
        {
            Console.WriteLine("Your certificate might be missing or the password is incorrect.");
            Log.Logger.Error(e.Message, e.StackTrace);
            throw;
        }


        for (int i = 0; i < 3; i++)
        {
            Console.Write("Enter password for your account: ");

            string password = readPassword();

            if (PasswordsFileUtil.CheckPassword(username, password))
            {
                Console.WriteLine("Login successful!");
                Username = username;
                return true;
            }
            else
            {
                if (i < 2) Console.WriteLine("Incorrect password. Please try again.");
            }
        }

        Registration.Suspend(username);

        Console.WriteLine("Too many login attempts. Login failed.\n" +
            "Your certificate is now suspended. You can reactivate it from the main menu.");
        return false;
    }

    internal static string readPassword()
    {
        string password = "";
        ConsoleKeyInfo key;
        do
        {
            key = Console.ReadKey(true);

            if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
            {
                password += key.KeyChar;
                Console.Write("*");
            }
            else if (key.Key == ConsoleKey.Backspace && password.Length > 0)
            {
                password = password.Substring(0, (password.Length - 1));
                Console.Write("\b \b");
            }
        } while (key.Key != ConsoleKey.Enter);
        Console.WriteLine();
        return password;
    }

    static byte[] GenerateNonce()
    {
        var nonce = new byte[12];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(nonce);
        return nonce;
    }

    public static bool IsCertificateTrusted(X509Certificate2 certificate, X509Certificate2 rootCertificate)
    {
        X509Chain chain = new X509Chain();
        chain.ChainPolicy.CustomTrustStore.Add(rootCertificate);
        chain.ChainPolicy.ExtraStore.Add(rootCertificate);
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        try
        {
            var chainBuilt = chain.Build(certificate);
            Log.Logger.Information(string.Format("Chain building status: {0}", chainBuilt));

            if (chainBuilt == false)
            {
                foreach (X509ChainStatus chainStatus in chain.ChainStatus)
                    Log.Logger.Information(string.Format("Chain error: {0} {1}", chainStatus.Status, chainStatus.StatusInformation));
                Console.WriteLine("Certificate not trusted.");
            }
        }
        catch (Exception ex)
        {
            Log.Logger.Information(ex.ToString());
        }

        bool isRevoked = false;
        if (File.Exists(crlFile))
        {
            var crl = new X509CrlParser().ReadCrl(File.ReadAllBytes(crlFile));
            isRevoked = crl.IsRevoked(new X509CertificateParser().ReadCertificate(certificate.RawData));
        }

        if (isRevoked)
        {
            Log.Logger.Information("Certificate revoked");
            Console.WriteLine("Your certificate is suspended. Reactivate it from the main menu or register a new account.");
            return false;
        }

        return true;
    }

    static byte[] UserSignedNonce(byte[] nonce, string username)
    {
        string keyFilePath = Registration.privatePath + $"{username}.key";

        Console.Write("Enter password for your certificate's private key: ");
        string passphrase = readPassword();

        var privateKeyParams = LoadPrivateKey(keyFilePath, passphrase);

        ISigner signer = SignerUtilities.GetSigner("SHA-256withRSA");
        signer.Init(true, privateKeyParams);

        signer.BlockUpdate(nonce, 0, nonce.Length);

        return signer.GenerateSignature();
    }

    internal static RsaPrivateCrtKeyParameters LoadPrivateKey(string filePath, string passphrase)
    {
        PemReader pemReader = new(new StreamReader(filePath), new MyPasswordFinder(passphrase));
        AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();

        return (RsaPrivateCrtKeyParameters)keyPair.Private;
    }


    class MyPasswordFinder : IPasswordFinder
    {
        internal MyPasswordFinder(string passphrase)
        {
            Passphrase = passphrase;
        }

        public string Passphrase { get; }

        public char[] GetPassword()
        {
            return Passphrase.ToCharArray();
        }
    }
}



