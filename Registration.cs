using Org.BouncyCastle.Pkcs;
using Serilog;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace SecureRepository;

internal class Registration
{
    internal static string wslStart = "wsl.exe";

    internal static string resources = "../../../resources/";
    internal static string caPath = Path.Combine(resources, "openssl/");
    internal static string cnfFile = Path.Combine(caPath, "openssl.cnf");
    internal static string requestsPath = Path.Combine(caPath, "requests/");
    internal static string privatePath = Path.Combine(caPath, "private/");
    internal static string certsPath = Path.Combine(caPath, "certs/");
    internal static string userCertsPath = Path.Combine(resources, "certs/");
    internal static string passwordsFile = Path.Combine(resources, "passwords.txt");

    static string rootCaPassword = "sigurnost"; // Password for root CA private key


    internal static void Register()
    {
        Console.Clear();

        Console.Write("Enter username: ");
        string username = Console.ReadLine();

        if (!PasswordsFileUtil.UniqueUsernameCheck(username))
        {
            Console.WriteLine("Username already exists.");
            return;
        }

        Console.WriteLine($"Hello {username}, You will need a certificate to use SecureRepository.\n" +
        $"You will need a password for the certificate's private key.\n" +
        $"Enter a strong password for your the certificate's private key: ");
        string userCertKeyPassword = Authentication.readPassword();

        string userKeyFile = Path.Combine(privatePath, username + ".key");
        string userCsrFile = Path.Combine(requestsPath, username + ".csr");
        string userCertFilename = username + ".pem";
        string userCertFile = Path.Combine(certsPath, userCertFilename);

        string genKeyCommand = $"openssl genrsa -out {userKeyFile} -aes128 -passout pass:{userCertKeyPassword} 2048";
        string csrCommand = $@"openssl req -new -config {cnfFile} -key {userKeyFile} -passin pass:{userCertKeyPassword} -out {userCsrFile}";
        string caSignCommand = $"openssl ca -batch -config {cnfFile} " +
            $"-in {userCsrFile} " +
            $"-out {userCertFile} " +
            $"-notext -passin pass:{rootCaPassword}";

        var startInfo = new ProcessStartInfo(wslStart, $"{genKeyCommand};{csrCommand};{caSignCommand}");
        startInfo.UseShellExecute = false;
        startInfo.RedirectStandardOutput = true;
        Process process = Process.Start(startInfo);
        process.WaitForExit();

        if (process.ExitCode != 0)
        {
            Log.Logger.Information("Couldn't create certificate - invalid user input");
            Console.WriteLine("Try again");
            return;
        }

        File.Copy(userCertFile, Path.Combine(userCertsPath, userCertFilename));

        Console.Clear();

        Console.WriteLine($"{username}, You will also need a password for your SecureRepository account.\n" +
            $"Enter a strong password for your account: ");
        string password = Authentication.readPassword();

        PasswordsFileUtil.AddPassword(username, password);

        KeystoreUtil.CreateKeystore(username, password);
        Directory.CreateDirectory(Path.Combine(Upload.displayPath, username));
        Directory.CreateDirectory(Path.Combine(Download.downloadPath, username));
    }

    internal static void Suspend(string username)
    {
        string caRevokeCommand = $"openssl ca -revoke " +
            $"{Path.Combine(certsPath, username)}.pem " +
            $"-crl_reason certificateHold " +
            $"-passin pass:{rootCaPassword} " +
            $"-gencrl -out {Authentication.crlFile} " +
            $"-config {cnfFile} -notext";

        var startInfo = new ProcessStartInfo(wslStart, $"{caRevokeCommand}");
        startInfo.UseShellExecute = false;
        startInfo.RedirectStandardOutput = true;
        Process process = Process.Start(startInfo);
        process.WaitForExit();
    }

    internal static void ReactivateCertificate()
    {
        Console.Write("Enter your username: ");
        var username = Console.ReadLine();

        if (PasswordsFileUtil.UniqueUsernameCheck(username))
        {
            Console.WriteLine("You need to register first.");
            return;
        }

        Console.Write("Enter password for your account: ");

        string password = Authentication.readPassword();

        if (!PasswordsFileUtil.CheckPassword(username, password))
        {
            Console.WriteLine("Incorrect password.");
            return;
        }
        try
        {

            using (X509Certificate2 clientCert = new(Path.Combine(certsPath, $"{username}.pem")))
            {

                var lines = File.ReadAllLines(Path.Combine(caPath, "index.txt"));
                if (lines == null || lines.Length == 0)
                {
                    return;
                }

                string pattern = @"^R(\s+\d{12}Z)(\s+\d{12}Z,certificateHold\s+)([0-9A-F]+)(.*)";
                Regex regex = new Regex(pattern);
                for (int i = 0; i < lines.Length; i++)
                {
                    string line = lines[i];
                    Match match = regex.Match(line);

                    if (match.Success && match.Groups[3].Value == clientCert.SerialNumber)
                    {
                        lines[i] = $"V{match.Groups[1].Value}\t\t{match.Groups[3].Value}{match.Groups[4].Value}";
                        break;
                    }
                }

                File.WriteAllLines(Path.Combine(caPath, "index.txt"), lines);

                string caRevokeCommand = $"openssl ca " +
                    $"-gencrl -out {Authentication.crlFile} " +
                    $"-config {cnfFile} -notext -passin pass:{rootCaPassword}";

                var startInfo = new ProcessStartInfo(wslStart, $"{caRevokeCommand}");
                startInfo.UseShellExecute = false;
                startInfo.RedirectStandardOutput = true;
                Process process = Process.Start(startInfo);
                process.WaitForExit();

            }
        }
        catch (Exception)
        {
            Console.WriteLine("Your certificate is missing.");
        }
    }
}

