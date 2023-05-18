using Org.BouncyCastle.Tls;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureRepository
{
    internal class WelcomeScreen
    {
        internal static void Show()
        {
            bool quit = false;

            while (!quit)
            {
                try
                {
                    Console.WriteLine("Please choose an option:");
                    Console.WriteLine("1. Register");
                    Console.WriteLine("2. Login");
                    Console.WriteLine("3. Reactivate Certificate");
                    Console.WriteLine("4. Clear Screen");
                    Console.WriteLine("0. Quit");

                    string input = Console.ReadLine();

                    switch (input)
                    {
                        case "1":
                            Registration.Register();
                            break;
                        case "2":
                            var obj = new Authentication();
                            if (obj.Login())
                                new RepositoryMenu() { Username = obj.Username }.Show();
                            break;
                        case "3":
                            Registration.ReactivateCertificate();
                            break;
                        case "4":
                            Console.Clear();
                            break;
                        case "0":
                            quit = true;
                            break;
                        default:
                            Console.WriteLine("Invalid input, please try again.");
                            break;
                    }

                    Console.WriteLine();

                }
                catch (Exception)
                {
                    Console.WriteLine("Invalid input.");
                }
            }
        }
    }
}
