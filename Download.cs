using Org.BouncyCastle.Crypto.Paddings;
using Serilog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.WebSockets;
using System.Text;
using System.Threading.Tasks;

namespace SecureRepository;

internal class Download
{
    internal static string downloadPath = Path.Combine(Registration.resources, "downloads/");

    internal static void DownloadFile(string username, string file, string asFile, byte[] master = null)
    {
        if (master == null)
        {
            Console.Write("Enter password for your certificate's private key: ");
            string passphrase = Authentication.readPassword();

            master = KeystoreUtil.GetMaster(username, passphrase);
        }

        try
        {
            byte[] delimiter = BitConverter.GetBytes('?');

            var visibleFile = Path.Combine(Upload.displayPath, $"{username}/", file);
            var fileBytes = KeystoreUtil.DecryptAesGcm(visibleFile, KeystoreUtil.Retrieve(KeystoreUtil.GetAlias(username, file), master));
            using (var fileStream = new MemoryStream(fileBytes))
            {
                var res = StripFilenameKeyname(delimiter, fileStream);

                List<byte[]> hiddenFileDataList = new List<byte[]>();
                int i = 0;
                while (res.Filename != null)
                {
                    string hiddenFilePath = Path.Combine(Upload.dataPath, res.Filename);
                    byte[] hiddenFileData = KeystoreUtil.DecryptAesGcm(hiddenFilePath, KeystoreUtil.Retrieve(res.Keyname, master));
                    if (hiddenFileData == null) break;

                    using (var byteStream = new MemoryStream(hiddenFileData))
                    {
                        res = StripFilenameKeyname(delimiter, byteStream);
                        hiddenFileDataList.Add(res.Data);
                    }
                    i++;
                }
                byte[] reassembledData = new byte[hiddenFileDataList.Sum(a => a.Length)];
                int offset = 0;
                foreach (byte[] hiddenFileData in hiddenFileDataList)
                {
                    Buffer.BlockCopy(hiddenFileData, 0, reassembledData, offset, hiddenFileData.Length);
                    offset += hiddenFileData.Length;
                }
                string finalPath = Path.Combine(downloadPath, $"{username}/", asFile);
                Directory.CreateDirectory(Path.GetDirectoryName(finalPath));
                File.WriteAllBytes(finalPath, reassembledData);
            }
        }
        catch (Exception)
        {
            Console.WriteLine("Could not download file.");
        }
    }

    internal record StripResult(byte[] Data, string Filename, string Keyname);
    private static StripResult StripFilenameKeyname(byte[] delimiter, MemoryStream fileStream)
    {
        byte[] filenameBytes = ReadBytesUntilDelimiter(fileStream, delimiter);
        if (filenameBytes.Length == 0)
        {
            byte[] rest = ReadBytes(fileStream);
            return new StripResult(rest, null, null);
        }

        string filename = Encoding.UTF8.GetString(filenameBytes);

        byte[] keynameBytes = ReadBytesUntilDelimiter(fileStream, delimiter);
        string keyname = Encoding.UTF8.GetString(keynameBytes);

        byte[] data = ReadBytes(fileStream);

        return new StripResult(data, filename, keyname);
    }

    private static byte[] ReadBytesUntilDelimiter(MemoryStream fileStream, byte[] delimiter)
    {
        using (var memoryStream = new MemoryStream())
        {
            int readByte;
            while ((readByte = fileStream.ReadByte()) != -1 && !delimiter.Contains((byte)readByte))
            {
                memoryStream.WriteByte((byte)readByte);
            }
            fileStream.ReadByte();
            return memoryStream.ToArray();
        }
    }

    private static byte[] ReadBytes(MemoryStream fileStream)
    {
        using (var memoryStream = new MemoryStream())
        {
            int readByte;
            while ((readByte = fileStream.ReadByte()) != -1)
            {
                memoryStream.WriteByte((byte)readByte);
            }
            return memoryStream.ToArray();
        }
    }

    internal static void DownloadFolder(string username, string repositoryPath, string asFolder)
    {
        Console.Write("Enter password for your certificate's private key: ");
        string passphrase = Authentication.readPassword();

        byte[] master = KeystoreUtil.GetMaster(username, passphrase);

        var userDisplayPath = Path.Combine(Upload.displayPath, $"{username}/");
        var visibleFolderPath = Path.Combine(userDisplayPath, repositoryPath);

        var userDownloadPath = Path.Combine(downloadPath, $"{username}/");
        string finalFolderPath = Path.Combine(userDownloadPath, asFolder);
        Directory.CreateDirectory(finalFolderPath);

        foreach (var file in Directory.GetFiles(visibleFolderPath, "*", SearchOption.AllDirectories))
        {
            var fromUserDisplay = Path.GetRelativePath(userDisplayPath, file);
            var subdirPath = Path.GetRelativePath(visibleFolderPath, file);
            var asFile = Path.Combine(finalFolderPath, subdirPath);
            if (Directory.Exists(file)) { Directory.CreateDirectory(asFile); continue; }
            DownloadFile(username, fromUserDisplay, asFile, master);
        }
    }

}
