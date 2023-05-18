using Org.BouncyCastle.Utilities.Encoders;
using System.Security.Cryptography;
using System.Text;

namespace SecureRepository
{
    internal class HmacUtil
    {
        static readonly int saltBase64ByteSize = 24;
        static readonly int hmacBase64ByteSize = 44;

        internal static byte[] GenerateHmac(byte[] data, byte[] key)
        {
            using (HMACSHA256 hmac = new HMACSHA256(key))
            {
                return hmac.ComputeHash(data);
            }
        }

        internal static byte[] GetKeyFromPassword(string password, byte[] salt)
        {
            const int Iterations = 100000;
            const int KeySize = 32;

            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations))
            {
                return pbkdf2.GetBytes(KeySize);
            }
        }

        public static void GenerateHmacForFile(string filePath, string password)
        {
            byte[] salt = new byte[16];

            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            byte[] key = GetKeyFromPassword(password, salt);

            GenerateHmacForFile(filePath, key);

            var saltBase64 = Encoding.UTF8.GetBytes(Convert.ToBase64String(salt));

            using (var fileStream = new FileStream(filePath, FileMode.Append))
            {
                fileStream.Write(saltBase64, 0, saltBase64.Length);
            }
        }

        public static void GenerateHmacForFile(string filePath, byte[] key)
        {
            byte[] fileBytes = File.ReadAllBytes(filePath);
            byte[] hmac = GenerateHmac(fileBytes, key);

            var hmacBase64 = Encoding.UTF8.GetBytes(Convert.ToBase64String(hmac));

            using (var fileStream = new FileStream(filePath, FileMode.Append))
            {
                fileStream.Write(hmacBase64, 0, hmacBase64.Length);
            }
        }

        public static bool VerifyHmacForFile(string filePath, string password)
        {
            byte[] fileBytes = File.ReadAllBytes(filePath);
            if (fileBytes == null || fileBytes.Length == 0) { return true; }
            byte[] hmacBase64Bytes = new byte[hmacBase64ByteSize];
            byte[] saltBase64Bytes = new byte[saltBase64ByteSize];

            using (var fileStream = new FileStream(filePath, FileMode.Open))
            {
                fileStream.Seek(-(saltBase64ByteSize + hmacBase64ByteSize), SeekOrigin.End);
                fileStream.Read(hmacBase64Bytes, 0, hmacBase64Bytes.Length);
                fileStream.Read(saltBase64Bytes, 0, saltBase64Bytes.Length);
            }

            char[] saltBase64Chars = new char[saltBase64ByteSize];
            char[] hmacBase64Chars = new char[hmacBase64ByteSize];

            Encoding.UTF8.GetChars(saltBase64Bytes, saltBase64Chars);
            byte[] salt = Convert.FromBase64CharArray(saltBase64Chars, 0, saltBase64ByteSize);

            Encoding.UTF8.GetChars(hmacBase64Bytes, hmacBase64Chars);
            byte[] hmac = Convert.FromBase64CharArray(hmacBase64Chars, 0, hmacBase64ByteSize);

            byte[] key = GetKeyFromPassword(password, salt);

            byte[] fileBytesWithoutHmac = fileBytes.Take(fileBytes.Length - hmacBase64ByteSize - saltBase64ByteSize).ToArray();
            byte[] generatedHMAC = GenerateHmac(fileBytesWithoutHmac, key);

            return hmac.SequenceEqual(generatedHMAC);
        }

        public static bool VerifyHmacForFile(string filePath, byte[] key)
        {
            byte[] fileBytes = File.ReadAllBytes(filePath);
            if (fileBytes == null || fileBytes.Length == 0) { return true; }
            byte[] hmacBase64Bytes = new byte[hmacBase64ByteSize];

            using (var fileStream = new FileStream(filePath, FileMode.Open))
            {
                fileStream.Seek(-hmacBase64ByteSize, SeekOrigin.End);
                fileStream.Read(hmacBase64Bytes, 0, hmacBase64Bytes.Length);
            }

            char[] hmacBase64Chars = new char[hmacBase64ByteSize];

            Encoding.UTF8.GetChars(hmacBase64Bytes, hmacBase64Chars);
            byte[] hmac = Convert.FromBase64CharArray(hmacBase64Chars, 0, hmacBase64ByteSize);

            byte[] fileBytesWithoutHmac = fileBytes.Take(fileBytes.Length - hmacBase64ByteSize).ToArray();
            byte[] generatedHMAC = GenerateHmac(fileBytesWithoutHmac, key);

            return hmac.SequenceEqual(generatedHMAC);
        }

        internal static void RemoveHmac(string file, bool fromPassword)
        {
            byte[] fileBytes = File.ReadAllBytes(file);
            if (fileBytes == null || fileBytes.Length == 0) { return; }


            int offset = fromPassword ? fileBytes.Length - hmacBase64ByteSize - saltBase64ByteSize
                : fileBytes.Length - hmacBase64ByteSize;
            byte[] fileBytesWithoutHmac = fileBytes.Take(offset).ToArray();

            using (var fileStream = new FileStream(file, FileMode.Create))
            {
                fileStream.Write(fileBytesWithoutHmac, 0, fileBytesWithoutHmac.Length);
            }
        }

        internal static byte[] SkipHmac(string file, bool fromPassword)
        {
            byte[] fileBytes = File.ReadAllBytes(file);
            int offset = fromPassword ? fileBytes.Length - hmacBase64ByteSize - saltBase64ByteSize
                : fileBytes.Length - hmacBase64ByteSize;
            return fileBytes.Take(offset).ToArray();
        }
    }
}

