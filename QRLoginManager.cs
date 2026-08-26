// QRLoginManager.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using QRCoder;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;

namespace QRLoginManager
{
    class Program
    {
        private const int SaltSize = 16;
        private const int NonceSize = 12;
        private const int KeySize = 32;
        private const int Iterations = 100000;

        static byte[] DeriveKey(string password, byte[] salt)
        {
            using (var derive = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256))
            {
                return derive.GetBytes(KeySize);
            }
        }

        static byte[] EncryptData(byte[] data, string password)
        {
            using (var aes = new AesGcm())
            {
                var salt = new byte[SaltSize];
                var nonce = new byte[NonceSize];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(salt);
                    rng.GetBytes(nonce);
                }
                var key = DeriveKey(password, salt);
                aes.Key = key;
                aes.Nonce = nonce;
                var ciphertext = new byte[data.Length];
                var tag = new byte[16];
                aes.Encrypt(data, ciphertext, tag);
                var combined = new byte[salt.Length + nonce.Length + ciphertext.Length + tag.Length];
                Buffer.BlockCopy(salt, 0, combined, 0, salt.Length);
                Buffer.BlockCopy(nonce, 0, combined, salt.Length, nonce.Length);
                Buffer.BlockCopy(ciphertext, 0, combined, salt.Length + nonce.Length, ciphertext.Length);
                Buffer.BlockCopy(tag, 0, combined, salt.Length + nonce.Length + ciphertext.Length, tag.Length);
                return combined;
            }
        }

        static byte[] DecryptData(byte[] encrypted, string password)
        {
            if (encrypted.Length < SaltSize + NonceSize + 16) throw new Exception("Invalid data");
            var salt = new byte[SaltSize];
            var nonce = new byte[NonceSize];
            var tag = new byte[16];
            Buffer.BlockCopy(encrypted, 0, salt, 0, salt.Length);
            Buffer.BlockCopy(encrypted, salt.Length, nonce, 0, nonce.Length);
            int cipherLen = encrypted.Length - salt.Length - nonce.Length - tag.Length;
            var ciphertext = new byte[cipherLen];
            Buffer.BlockCopy(encrypted, salt.Length + nonce.Length, ciphertext, 0, cipherLen);
            Buffer.BlockCopy(encrypted, salt.Length + nonce.Length + cipherLen, tag, 0, tag.Length);
            var key = DeriveKey(password, salt);
            using (var aes = new AesGcm())
            {
                aes.Key = key;
                aes.Nonce = nonce;
                var plaintext = new byte[cipherLen];
                aes.Decrypt(ciphertext, plaintext, tag);
                return plaintext;
            }
        }

        static List<string> GenerateCodes(int count, int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var rng = new Random();
            var codes = new List<string>();
            for (int i = 0; i < count; i++)
            {
                var sb = new StringBuilder();
                for (int j = 0; j < length; j++)
                    sb.Append(chars[rng.Next(chars.Length)]);
                codes.Add(sb.ToString());
            }
            return codes;
        }

        class BackupData
        {
            public string Created { get; set; }
            public List<string> Codes { get; set; }
        }

        static void SaveToFile(BackupData data, string password, string filename)
        {
            var json = JsonSerializer.SerializeToUtf8Bytes(data);
            var encrypted = EncryptData(json, password);
            File.WriteAllBytes(filename, encrypted);
            Console.WriteLine($"Saved encrypted backup to {filename}");
        }

        static BackupData LoadFromFile(string filename, string password)
        {
            var encrypted = File.ReadAllBytes(filename);
            var decrypted = DecryptData(encrypted, password);
            return JsonSerializer.Deserialize<BackupData>(decrypted);
        }

        static void ListCodes(string filename, string password)
        {
            var data = LoadFromFile(filename, password);
            Console.WriteLine($"Backup: {filename}");
            Console.WriteLine($"Created: {data.Created}");
            Console.WriteLine("Codes:");
            foreach (var code in data.Codes)
                Console.WriteLine($"  {code}");
        }

        static void GenerateQR(string filename, string password, string output)
        {
            var data = LoadFromFile(filename, password);
            var codesStr = string.Join("\n", data.Codes);
            using (var qrGenerator = new QRCodeGenerator())
            {
                var qrData = qrGenerator.CreateQrCode(codesStr, QRCodeGenerator.ECCLevel.Q);
                var qrCode = new QRCode(qrData);
                using (var qrImage = qrCode.GetGraphic(20))
                {
                    qrImage.Save(output, System.Drawing.Imaging.ImageFormat.Png);
                }
            }
            Console.WriteLine($"QR code saved to {output}");
        }

        static void CheckCode(string filename, string password, string code)
        {
            var data = LoadFromFile(filename, password);
            if (data.Codes.Contains(code))
                Console.WriteLine($"Code '{code}' is valid (found in backup).");
            else
                Console.WriteLine($"Code '{code}' is NOT in backup.");
        }

        static void Main(string[] args)
        {
            var dict = new Dictionary<string, string>();
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i].StartsWith("--"))
                {
                    var key = args[i].Substring(2);
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
                        dict[key] = args[++i];
                    else
                        dict[key] = "";
                }
            }

            try
            {
                if (dict.ContainsKey("generate"))
                {
                    int count = int.Parse(dict["generate"]);
                    string output = dict.GetValueOrDefault("output");
                    string password = dict.GetValueOrDefault("password");
                    if (string.IsNullOrEmpty(output) || string.IsNullOrEmpty(password))
                        throw new Exception("--output and --password required");
                    var data = new BackupData { Created = DateTime.UtcNow.ToString("o"), Codes = GenerateCodes(count, 8) };
                    SaveToFile(data, password, output);
                }
                else if (dict.ContainsKey("list"))
                {
                    string file = dict["list"];
                    string password = dict.GetValueOrDefault("password");
                    if (string.IsNullOrEmpty(password))
                        throw new Exception("--password required");
                    ListCodes(file, password);
                }
                else if (dict.ContainsKey("qr"))
                {
                    string file = dict["qr"];
                    string password = dict.GetValueOrDefault("password");
                    string output = dict.GetValueOrDefault("output");
                    if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(output))
                        throw new Exception("--password and --output required for QR");
                    GenerateQR(file, password, output);
                }
                else if (dict.ContainsKey("check"))
                {
                    string code = dict["check"];
                    string file = dict.GetValueOrDefault("list");
                    string password = dict.GetValueOrDefault("password");
                    if (string.IsNullOrEmpty(file) || string.IsNullOrEmpty(password))
                        throw new Exception("--list and --password required for check");
                    CheckCode(file, password, code);
                }
                else
                {
                    Console.WriteLine("Use --help for usage.");
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                Environment.Exit(1);
            }
        }
    }
}
