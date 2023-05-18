using Org.BouncyCastle.Asn1.X509;
using System;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace SecureRepository;

internal class RepositoryMenu
{
    internal string Username { get; set; }

    internal void Show()
    {
        while (true)
        {
            Console.WriteLine();
            Console.WriteLine("Select an option:");
            Console.WriteLine("1. Upload file");
            Console.WriteLine("2. Upload folder");
            Console.WriteLine("3. Download file");
            Console.WriteLine("4. Download folder");
            Console.WriteLine("5. Browse");
            Console.WriteLine("6. Clear screen");
            Console.WriteLine("0. Exit");

            string input = Console.ReadLine();

            switch (input)
            {
                case "1":
                    UploadFile();
                    break;
                case "2":
                    UploadFolder();
                    break;
                case "3":
                    DownloadFile();
                    break;
                case "4":
                    DownloadFolder();
                    break;
                case "5":
                    Browse();
                    break;
                case "6":
                    Console.Clear();
                    break;
                case "0":
                    return;
                default:
                    Console.WriteLine("Invalid option.");
                    break;
            }

            Console.WriteLine();
        }
    }

    void UploadFile()
    {
        Console.WriteLine();
        Console.WriteLine("Upload file option selected.");
        Console.WriteLine("Enter absolute path of the file you want to upload:");
        string absolutePath = Console.ReadLine();
        if (!File.Exists(absolutePath))
        {
            Console.WriteLine("Invalid absolute path.\n");
            return;
        }
        Console.WriteLine("Enter path to store on SecureRepository (eg. images/bouncy_castle.png):");
        string asFile = Console.ReadLine();
        Upload.UploadFile(Username, absolutePath, asFile);
    }

    void UploadFolder()
    {
        Console.WriteLine();
        Console.WriteLine("Upload folder option selected.");
        Console.WriteLine("Enter absolute path of the folder you want to upload:");
        string absolutePath = Console.ReadLine();
        if (!Directory.Exists(absolutePath))
        {
            Console.WriteLine("Invalid absolute path.\n");
            return;
        }
        Console.WriteLine("Enter path to store on SecureRepository (eg. images/tournament):");
        string asFolder = Console.ReadLine();
        Upload.UploadFolder(Username, absolutePath, asFolder);
    }

    void DownloadFile()
    {
        Console.WriteLine();
        Console.WriteLine("Download file option selected.");
        Console.WriteLine("Enter path of the file you want to download:");
        string repositoryPath = Console.ReadLine();
        if (!File.Exists(Path.Combine(Upload.displayPath, $"{Username}/", repositoryPath)))
        {
            Console.WriteLine("Invalid path.\n");
            return;
        }
        Console.WriteLine("Enter the path and name for the downloaded file, relative to your downloads folder:");
        string asFile = Console.ReadLine();

        Download.DownloadFile(Username, repositoryPath, asFile);
    }

    void DownloadFolder()
    {
        Console.WriteLine();
        Console.WriteLine("Download folder option selected.");
        Console.WriteLine("Enter path of the folder you want to download:");
        string repositoryPath = Console.ReadLine();
        if (!Directory.Exists(Path.Combine(Upload.displayPath, $"{Username}/", repositoryPath)))
        {
            Console.WriteLine("Invalid path.\n");
            return;
        }
        Console.WriteLine("Enter the path and name for the downloaded folder, relative to your downloads folder:");
        string asFolder = Console.ReadLine();
        Download.DownloadFolder(Username, repositoryPath, asFolder);
    }

    void Browse()
    {
        Console.WriteLine("Browse option selected.");
        string rootPath = Path.Combine(Upload.displayPath, $"{Username}/");
        string currentPath = rootPath;
        string displayPath = Path.GetRelativePath(rootPath, currentPath).Replace(".", "/");

        while (true)
        {
            Console.WriteLine();
            Console.WriteLine($"Current directory: {displayPath}");
            Console.WriteLine("Enter " +
                "\n\t'cd [folder name]' to navigate to a subdirectory, " +
                "\n\t'back' to go up one level, " +
                "\n\t'ls' to list files and folders in the current directory, " +
                "\n\t'download [file or folder]' to download from current directory, " +
                "\n\t'cls' to clear the screen, " +
                "\n\t'exit' to return to the main menu:");

            string input = Console.ReadLine();
            
            Console.WriteLine();

            if (input == "back")
            {
                DirectoryInfo currentDir = new DirectoryInfo(currentPath);
                if (Path.GetDirectoryName(displayPath) != displayPath && displayPath != "/")
                {
                    currentPath = currentDir.Parent.FullName;
                    displayPath = Path.GetRelativePath(rootPath, currentPath).Replace(".", "/");
                }
                else
                {
                    Console.WriteLine("Cannot navigate beyond the root directory.");
                }
            }
            else if (input.StartsWith("cd "))
            {
                string subDirName = input.Substring(3);
                if (subDirName.Contains(".."))
                {
                    Console.WriteLine("Invalid input.");
                }
                else
                {

                    string newPath = Path.Combine(currentPath, subDirName);

                    if (Directory.Exists(newPath))
                    {
                        currentPath = newPath;
                        displayPath = Path.GetRelativePath(rootPath, currentPath).Replace(".", "/");
                    }
                    else
                    {
                        Console.WriteLine("Invalid directory path or path is outside of the root directory.");
                    }
                }
            }
            else if (input == "ls")
            {
                Console.WriteLine("Files and folders in the current directory:");

                try
                {
                    foreach (string folderPath in Directory.GetDirectories(currentPath))
                    {
                        Console.WriteLine($"[Folder] {Path.GetFileName(folderPath)}");
                    }

                    foreach (string filePath in Directory.GetFiles(currentPath))
                    {
                        Console.WriteLine($"[File] {Path.GetFileName(filePath)}");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error listing files and folders: {ex.Message}");
                }
            }
            else if (input.StartsWith("download "))
            {
                string toDownload = input.Substring(9);
                if (toDownload.Contains(".."))
                {
                    Console.WriteLine("Invalid input");
                }
                else
                {
                    var currentFromRoot = displayPath == "/" ? "" : displayPath;
                    string finalPath = Path.Combine(currentFromRoot, toDownload);
                    if (File.Exists(Path.Combine(currentPath, toDownload)))
                    {
                        Console.WriteLine("Enter the path and name for the downloaded file, relative to your downloads folder:");
                        string asFile = Console.ReadLine();

                        Download.DownloadFile(Username, finalPath, asFile);
                    }
                    else if (Directory.Exists(Path.Combine(currentPath, toDownload)))
                    {
                        Console.WriteLine("Enter the path and name for the downloaded, relative to your downloads folder:");
                        string asFolder = Console.ReadLine();

                        Download.DownloadFolder(Username, finalPath, asFolder);
                    }
                    else
                    {
                        Console.WriteLine("Invalid input.");
                    }
                }
            }
            else if (input == "cls")
            {
                Console.Clear();
            }
            else if (input == "exit")
            {
                break;
            }
            else
            {
                Console.WriteLine("Invalid input.");
            }
        }
    }
}
