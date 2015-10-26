using System;
using System.CodeDom;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace LBitcoin
{
    class ReferenceLib
    {

        public static byte[] Base58ToByteArray(string base58)
        {
            Org.BouncyCastle.Math.BigInteger bi2 = new Org.BouncyCastle.Math.BigInteger("0");
            string b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

            bool IgnoreChecksum = false;

            foreach (char c in base58)
            {
                if (b58.IndexOf(c) != -1)
                {
                    bi2 = bi2.Multiply(new Org.BouncyCastle.Math.BigInteger("58"));
                    bi2 = bi2.Add(new Org.BouncyCastle.Math.BigInteger(b58.IndexOf(c).ToString()));
                }
                else if (c == '?')
                {
                    IgnoreChecksum = true;
                }
                else
                {
                    return null;
                }
            }

            byte[] bb = bi2.ToByteArrayUnsigned();

            // interpret leading '1's as leading zero bytes
            foreach (char c in base58)
            {
                if (c != '1') break;
                byte[] bbb = new byte[bb.Length + 1];
                Array.Copy(bb, 0, bbb, 1, bb.Length);
                bb = bbb;
            }

            if (bb.Length < 4) return null;

            if (IgnoreChecksum == false)
            {
                SHA256CryptoServiceProvider sha256 = new SHA256CryptoServiceProvider();
                byte[] checksum = sha256.ComputeHash(bb, 0, bb.Length - 4);
                checksum = sha256.ComputeHash(checksum);
                for (int i = 0; i < 4; i++)
                {
                    if (checksum[i] != bb[bb.Length - 4 + i]) return null;
                }
            }

            byte[] rv = new byte[bb.Length - 4];
            Array.Copy(bb, 0, rv, 0, bb.Length - 4);
            return rv;
        }

        public static string ByteArrayToBase58Check(byte[] ba)
        {
            byte[] bb = new byte[ba.Length + 4];
            Array.Copy(ba, bb, ba.Length);
            SHA256CryptoServiceProvider sha256 = new SHA256CryptoServiceProvider();
            byte[] thehash = sha256.ComputeHash(ba);
            thehash = sha256.ComputeHash(thehash);
            for (int i = 0; i < 4; i++) bb[ba.Length + i] = thehash[i];
            return ByteArrayToBase58(bb);
        }

        public static string ByteArrayToBase58(byte[] ba)
        {
            Org.BouncyCastle.Math.BigInteger addrremain = new Org.BouncyCastle.Math.BigInteger(1, ba);

            Org.BouncyCastle.Math.BigInteger big0 = new Org.BouncyCastle.Math.BigInteger("0");
            Org.BouncyCastle.Math.BigInteger big58 = new Org.BouncyCastle.Math.BigInteger("58");

            string b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

            string rv = "";

            while (addrremain.CompareTo(big0) > 0)
            {
                int d = Convert.ToInt32(addrremain.Mod(big58).ToString());
                addrremain = addrremain.Divide(big58);
                rv = b58.Substring(d, 1) + rv;
            }

            // handle leading zeroes
            foreach (byte b in ba)
            {
                if (b != 0) break;
                rv = "1" + rv;

            }
            return rv;
        }


        public static byte[] ValidateAndGetHexPublicHash(string pubHash)
        {
            byte[] hex = GetHexBytes(pubHash, 20);

            if (hex == null || hex.Length != 20)
            {
                throw new Exception("Hex is not 20 bytes.");
                return null;
            }
            return hex;
        }

        public static byte[] ValidateAndGetHexPublicKey(string publicHex)
        {
            byte[] hex = GetHexBytes(publicHex, 64);

            if (hex == null || hex.Length < 64 || hex.Length > 65)
            {
                throw new Exception("Hex is not 64 or 65 bytes");
                return null;
            }

            // if leading 00, change it to 0x80
            if (hex.Length == 65)
            {
                if (hex[0] == 0 || hex[0] == 4)
                {
                    hex[0] = 4;
                }
                else
                {
                    throw new Exception("Not a valid public key");
                    return null;
                }
            }

            // add 0x80 byte if not present
            if (hex.Length == 64)
            {
                byte[] hex2 = new byte[65];
                Array.Copy(hex, 0, hex2, 1, 64);
                hex2[0] = 4;
                hex = hex2;
            }
            return hex;
        }

        public static byte[] GetHexBytes(string source, int minimum)
        {
            byte[] hex = GetHexBytes(source);
            if (hex == null) return null;
            // assume leading zeroes if we're short a few bytes
            if (hex.Length > (minimum - 6) && hex.Length < minimum)
            {
                byte[] hex2 = new byte[minimum];
                Array.Copy(hex, 0, hex2, minimum - hex.Length, hex.Length);
                hex = hex2;
            }
            // clip off one overhanging leading zero if present
            if (hex.Length == minimum + 1 && hex[0] == 0)
            {
                byte[] hex2 = new byte[minimum];
                Array.Copy(hex, 1, hex2, 0, minimum);
                hex = hex2;

            }

            return hex;
        }

        public static byte[] GetHexBytes(string source)
        {
            List<byte> bytes = new List<byte>();
            // copy s into ss, adding spaces between each byte
            string s = source;
            string ss = "";
            int currentbytelength = 0;
            foreach (char c in s.ToCharArray())
            {
                if (c == ' ')
                {
                    currentbytelength = 0;
                }
                else
                {
                    currentbytelength++;
                    if (currentbytelength == 3)
                    {
                        currentbytelength = 1;
                        ss += ' ';
                    }
                }
                ss += c;
            }

            foreach (string b in ss.Split(' '))
            {
                int v = 0;
                if (b.Trim() == "") continue;
                foreach (char c in b.ToCharArray())
                {
                    if (c >= '0' && c <= '9')
                    {
                        v *= 16;
                        v += (c - '0');

                    }
                    else if (c >= 'a' && c <= 'f')
                    {
                        v *= 16;
                        v += (c - 'a' + 10);
                    }
                    else if (c >= 'A' && c <= 'F')
                    {
                        v *= 16;
                        v += (c - 'A' + 10);
                    }

                }
                v &= 0xff;
                bytes.Add((byte)v);
            }
            return bytes.ToArray();
        }

        public static byte[] ValidateAndGetHexPrivateKey(string hexStr, byte leadingbyte)
        {
            byte[] hex = GetHexBytes(hexStr, 32);

            if (hex == null || hex.Length < 32 || hex.Length > 33)
            {
                throw new Exception("Hex is not 32 or 33 bytes.");
                return null;
            }

            // if leading 00, change it to 0x80
            if (hex.Length == 33)
            {
                if (hex[0] == 0 || hex[0] == 0x80)
                {
                    hex[0] = 0x80;
                }
                else
                {
                    throw new Exception("Not a valid private key");
                    return null;
                }
            }

            // add 0x80 byte if not present
            if (hex.Length == 32)
            {
                byte[] hex2 = new byte[33];
                Array.Copy(hex, 0, hex2, 1, 32);
                hex2[0] = 0x80;
                hex = hex2;
            }

            hex[0] = leadingbyte;
            return hex;

        }

        public static string ByteArrayToString(byte[] ba, int offset, int count)
        {
            string rv = "";
            int usedcount = 0;
            for (int i = offset; usedcount < count; i++, usedcount++)
            {
                rv += String.Format("{0:X2}", ba[i]) + " ";
            }
            return rv;
        }
    }
}