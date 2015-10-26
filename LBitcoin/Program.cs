using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace LBitcoin
{
    class Program
    {
        public static void Main(String[] args)
        {
            var privateKey = GeneratePrivateKey();
            var publicKey = GetPublicKey(privateKey);
            var publicHash = GetPublicHash(publicKey);
            var address = CreateAddress(publicHash);

            Console.WriteLine(address);
            Console.ReadLine();
        }

        public static string CreateAddress(string publicHash)
        {
            byte[] publicHashHex = ReferenceLib.ValidateAndGetHexPublicHash(publicHash);
            if (publicHashHex == null)
                throw new Exception("error");

            byte[] hex2 = new byte[21];
            Array.Copy(publicHashHex, 0, hex2, 1, 20);

            //var cointype = 0; //MainNet
            var cointype = 111;//TextNet

            hex2[0] = (byte)(cointype & 0xff);
            var address = ReferenceLib.ByteArrayToBase58Check(hex2);

            return address;
        }

        public static string GetPublicHash(string publicKey)
        {
            byte[] publicHex = ReferenceLib.ValidateAndGetHexPublicKey(publicKey);

            if (publicHex == null)
                throw new Exception("error");

            SHA256CryptoServiceProvider sha256 = new SHA256CryptoServiceProvider();
            byte[] shaofpubkey = sha256.ComputeHash(publicHex);

            RIPEMD160 rip = System.Security.Cryptography.RIPEMD160.Create();
            byte[] ripofpubkey = rip.ComputeHash(shaofpubkey);

            var publicHash = ByteArrayToString(ripofpubkey);

            return publicHash;
        }
        public static string GetPublicKey(string privateKey)
        {
            var hexPrivateKey = ReferenceLib.ValidateAndGetHexPrivateKey(privateKey, 0x00);
            if (hexPrivateKey == null)
                throw new Exception("error");

            var ps = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
            Org.BouncyCastle.Math.BigInteger Db = new Org.BouncyCastle.Math.BigInteger(hexPrivateKey);
            ECPoint dd = ps.G.Multiply(Db);

            byte[] pubaddr = new byte[65];
            byte[] Y = dd.Y.ToBigInteger().ToByteArray();
            Array.Copy(Y, 0, pubaddr, 64 - Y.Length + 1, Y.Length);
            byte[] X = dd.X.ToBigInteger().ToByteArray();
            Array.Copy(X, 0, pubaddr, 32 - X.Length + 1, X.Length);
            pubaddr[0] = 4;

            var publicKey = ByteArrayToString(pubaddr);

            return publicKey;
        }

        public static string WifToPrivateKey()
        {
            var wif = "5KTiwJBGNRMQc1ACkm18FKzjT7VP1ezaVU5cHC9vWRMX2zDkKPz";
            var hex = ReferenceLib.Base58ToByteArray(wif);

            if (hex == null)
            {
                var length = wif.Length;
                if (length >= 50 && length <= 52)
                {
                    throw new Exception("Private key is not valid");
                }
            }
            if (hex.Length != 33)
            {
                throw new Exception("WIF private key is not valid, wrong byte count, should be 33, was " + hex.Length);
            }

            var privateKey = ByteArrayToString(hex, 1);
            return privateKey;
        }

        public static string GeneratePrivateKey()
        {
            ECKeyPairGenerator gen = new ECKeyPairGenerator();
            var secureRandom = new SecureRandom(new byte[] { 1, 2, 3, 4, 6 });

            var ps = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
            var ecParams = new ECDomainParameters(ps.Curve, ps.G, ps.N, ps.H);
            var keyGenParam = new ECKeyGenerationParameters(ecParams, secureRandom);
            gen.Init(keyGenParam);

            AsymmetricCipherKeyPair kp = gen.GenerateKeyPair();

            ECPrivateKeyParameters priv = (ECPrivateKeyParameters)kp.Private;

            byte[] hexpriv = priv.D.ToByteArrayUnsigned();
            var privateKey = ByteArrayToString(hexpriv);

            return privateKey;
        }

        public static string ByteArrayToString(byte[] bytes, int offset=0)
        {
            bytes = bytes.ToList().Skip(offset).ToArray();
            var result = BitConverter.ToString(bytes).Replace("-", " ");
            return result;
        }
    }
}