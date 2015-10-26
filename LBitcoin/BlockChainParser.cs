using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

namespace BlockchainParser
{
    class BlockChainParser
    {
        public static bool  ConsoleOut { get; set; }
        public static BinaryReader BinaryReader { get; set; }
        public static void WriteLine(string pattern = "", params object[] p)
        {
            if (ConsoleOut)
            {
                if (p.Length == 0)
                {
                    Console.WriteLine();
                    return;
                }
                    

                Console.WriteLine("{0}: {1}", p);
            }
               
        }

        public static void Mainx(String[] args)
        {
            ConsoleOut = true;

            var path = @"C:\Users\machine\AppData\Roaming\Bitcoin\blocks\blk00000.dat";

            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read))
            {
                using (BinaryReader = new BinaryReader(fs, new ASCIIEncoding()))
                {
                    var stopwatch = new Stopwatch();
                    stopwatch.Start();

                    var count = 0;
                    while(true)
                    {
                        var magicNumber = GetMagicNumber(4, "MagicNumber");
                        if (magicNumber == null)
                        {
                            stopwatch.Stop();
                            Console.WriteLine("parsed {0} transactions in {1} seconds",count,stopwatch.Elapsed.Seconds);
                            break;
                        }

                        ByteArrayToUInt32(4, "blockSize");

                        // Block Header
                        ByteArrayToUInt32(4, "version");
                        ByteArrayToHex(32, "hashPrevBlock");
                        ByteArrayToHex(32, "hashMerkleRoot");
                        ByteArrayToTime(4, "Time");
                        ByteArrayToHex(4, "bits");
                        ByteArrayToHex(4, "nonce");
                        // END Block header

                        WriteLine();
                        var transactionCount = ReadVarInt("transactionCount");
      
                        WriteLine();

                        for (var i = 0; i < transactionCount; i++)
                        {
                            ByteArrayToUInt32(4, "version no");
                            var inputCounter = ReadVarInt("inputCounter");

                            for (var j = 0; j < inputCounter; j++)
                            {
                                ByteArrayToHex(32, "previousTxHash");
                                ByteArrayToHex(4, "PreviousTxOutIndex");
                                var txInScriptLength = ReadVarInt("txInScriptLength");
                               
                                ByteArrayToString((int) txInScriptLength, "ScriptSig");
                                ByteArrayToHex(4, "sequence");
                            }

                            var outputCounter = ReadVarInt("txInScriptLength");

                            for (var j = 0; j < outputCounter; j++)
                            {
                                ByteArrayToUInt64(8, "amount");
                                var pkScriptLength = ReadVarInt("pkScriptLength");

                                var arr = ByteArrayToByteArray((int)pkScriptLength, "pk_script");
                            }

                            ByteArrayToUInt32(4, "timelock");
                            WriteLine("--------------------------------------------");
                            WriteLine("");
                            count++;
                        }  
                    }

                    Console.ReadLine();
                }
            }
        }

        public static long ReadVarInt(string name)
        {
            var t = BinaryReader.ReadByte();
            if (t < 0xfd)
            {
                WriteLine("{0}: {1}", name, t);
                return t;
            }

            if (t == 0xfd)
            {
                var value = BinaryReader.ReadInt16();
                WriteLine("{0}: {1}", name, value);
                return value;
            }


            if (t == 0xfe)
            {
                var value = BinaryReader.ReadInt32();
                WriteLine("{0}: {1}", name, value);
                return value;
            }  

            if (t == 0xff)
            {
                var value = BinaryReader.ReadInt64(); 
                WriteLine("{0}: {1}", name, value);
                return value;
            }

            throw new InvalidDataException("Reading Var Int");
        }

        private static void ByteArrayToTime(int n, string name)
        {
            var timeInt = BitConverter.ToInt32(BinaryReader.ReadBytes(n), 0);
            var time = ConvertFromUnixTimestamp(timeInt);
            WriteLine("{0}: {1}", name, time);
        }

        private static string ByteArrayToHex(int n, string name)
        {
            var value = BitConverter.ToString(BinaryReader.ReadBytes(n)).Replace("-", "");
            WriteLine("{0}: {1}", name, value);
            return value;
        }

        private static List<string> ByteArrayToHexArray(int n, string name)
        {
            var value = BitConverter.ToString(BinaryReader.ReadBytes(n));
            var split = value.Split(new[] { "-" }, StringSplitOptions.None).ToList();
            WriteLine("{0}: {1}", name, value);
            return split;
        }

        private static byte[] ByteArrayToByteArray(int n, string name)
        {
            var value = BinaryReader.ReadBytes(n);
            WriteLine("{0}: {1}", name, value);
            return value;
        }

        private static byte[] GetMagicNumber(int n, string name)
        {
            var bytes = BinaryReader.ReadBytes(n);
            if (bytes.Length == 0)
                return null;

            var value = BitConverter.ToString(bytes).Replace("-", "");
            WriteLine("{0}: {1}", name, value);

            return bytes;
        }


        private static uint ByteArrayToUInt32(int n, string name)
        {
            var  value = BinaryReader.ReadUInt32();
            WriteLine("{0}: {1}", name, value);
            return value;
        }

        private static ulong ByteArrayToUInt64(int n, string name)
        {
            var bytes = BinaryReader.ReadBytes(n);
            var value = BitConverter.ToUInt64(bytes, 0);
            WriteLine("{0}: {1}", name, value);
            return value;
        }

        private static void ByteArrayToString(int n, string name)
        {
            var bytes = BinaryReader.ReadBytes(n);
            var value = System.Text.Encoding.UTF8.GetString(bytes);
            WriteLine("{0}: {1}", name, value);
        }

        public static DateTime ConvertFromUnixTimestamp(double timestamp)
        {
            var origin = new DateTime(1970, 1, 1, 0, 0, 0, 0);
            return origin.AddSeconds(timestamp);
        }
    }
}