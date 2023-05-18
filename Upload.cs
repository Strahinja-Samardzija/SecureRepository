using Org.BouncyCastle.Asn1.Icao;
using System;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SecureRepository
{
    internal class Upload
    {
        internal static string dataPath = Path.Combine(Registration.resources, "data/");
        internal static string displayPath = Path.Combine(Registration.resources, "display/");

        internal static void UploadFile(string username, string absolutePath, string asFile, byte[] master = null)
        {
            Random rnd = new Random();
            int N = rnd.Next(4, 31);

            var fileBytes = File.ReadAllBytes(absolutePath);

            string[] strings = new string[N];

            for (int i = 0; i < N; i++)
            {
                StringBuilder str = new("");
                int length = rnd.Next(1, 5);

                for (int j = 0; j < length; j++)
                {
                    str.Append(rnd.Next(0, 2));
                    if (j != length - 1)
                        str.Append('/');
                }
                strings[i] = str.ToString();
            }
            string[] keynames = new string[N];
            for (int i = 0; i < N; i++)
            {
                keynames[i] = Path.GetRandomFileName();
            }

            for (int i = 0; i < N; i++)
            {
                Directory.CreateDirectory(Path.Combine(dataPath, strings[i]));
            }

            var parts = SplitFile(fileBytes, N);


            var visibleFile = Path.Combine(displayPath, $"{username}/", asFile);
            Directory.CreateDirectory(Path.GetDirectoryName(visibleFile));

            byte[] delimiter = BitConverter.GetBytes('?');

            for (int i = 0; i < N; i++)
            {
                strings[i] += $"\\{Path.GetRandomFileName()}";
            }


            using (var fileStream = new FileStream(visibleFile, FileMode.Create))
            {
                var nextPart = Encoding.UTF8.GetBytes(strings[0]);
                fileStream.Write(nextPart, 0, nextPart.Length);
                fileStream.Write(delimiter, 0, delimiter.Length);

                var keyFile = Encoding.UTF8.GetBytes(keynames[0]);
                fileStream.Write(keyFile, 0, keyFile.Length);
                fileStream.Write(delimiter, 0, delimiter.Length);
            }

            if (master == null)
            {
                Console.Write("Enter password for your certificate's private key: ");
                string passphrase = Authentication.readPassword();

                master = KeystoreUtil.GetMaster(username, passphrase);
            }

            var aesObjectVisible = Aes.Create();
            aesObjectVisible.KeySize = 128;
            aesObjectVisible.GenerateKey();
            byte[] keyVisible = aesObjectVisible.Key;
            KeystoreUtil.Store(KeystoreUtil.GetAlias(username, asFile), keyVisible, master);
            KeystoreUtil.EncryptAesGcm(visibleFile, keyVisible, File.ReadAllBytes(visibleFile));
            HmacUtil.GenerateHmacForFile(visibleFile, keyVisible);

            for (int i = 0; i < N; i++)
            {
                string file = Path.Combine(dataPath, strings[i]);

                using (var fileStream = new FileStream(file, FileMode.Create))
                {
                    if (i != N - 1)
                    {
                        var nextPart = Encoding.UTF8.GetBytes(strings[i + 1]);
                        fileStream.Write(nextPart, 0, nextPart.Length);
                        fileStream.Write(delimiter, 0, delimiter.Length);

                        var keyFile = Encoding.UTF8.GetBytes(keynames[i + 1]);
                        fileStream.Write(keyFile, 0, keyFile.Length);
                        fileStream.Write(delimiter, 0, delimiter.Length);
                    }
                    else
                    {
                        fileStream.Write(delimiter, 0, delimiter.Length);
                    }
                    fileStream.Write(parts[i], 0, parts[i].Length);
                }

                var aesObject = Aes.Create();
                aesObject.KeySize = 128;
                aesObject.GenerateKey();
                byte[] key = aesObject.Key;
                KeystoreUtil.Store(keynames[i], key, master);
                KeystoreUtil.EncryptAesGcm(file, key, File.ReadAllBytes(file));
                HmacUtil.GenerateHmacForFile(file, key);
            }
        }

        internal static void UploadFolder(string username, string absolutePath, string asFolder)
        {
            Console.Write("Enter password for your certificate's private key: ");
            string passphrase = Authentication.readPassword();

            byte[] master = KeystoreUtil.GetMaster(username, passphrase);

            foreach (var file in Directory.GetFiles(absolutePath, "*", SearchOption.AllDirectories))
            {
                var relativePath = file.Substring(absolutePath.Length + 1);
                var filePath = Path.Combine(asFolder, relativePath);
                if (Directory.Exists(file)) { Directory.CreateDirectory(filePath); continue; }
                UploadFile(username, file, filePath, master);
            }
        }

        private static List<byte[]> SplitFile(byte[] data, int numParts)
        {
            int minPartSize = data.Length / 60;
            int maxPartSize = data.Length * 3 / 4;

            List<byte[]> parts = new List<byte[]>();

            int remainingSize = data.Length;
            int remainingParts = numParts;

            while (remainingParts > 0)
            {
                int nextPartSize;
                if (remainingParts == 1)
                {
                    nextPartSize = remainingSize;
                }
                else
                {
                    int maxNextPartSize = Math.Min(maxPartSize, remainingSize - remainingParts * minPartSize);

                    nextPartSize = new Random().Next(minPartSize, maxNextPartSize + 1);
                }

                byte[] partData = new byte[nextPartSize];
                Array.Copy(data, data.Length - remainingSize, partData, 0, nextPartSize);

                parts.Add(partData);
                remainingSize -= nextPartSize;
                remainingParts--;
            }
            return parts;
        }
    }
}
