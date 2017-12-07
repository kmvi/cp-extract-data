using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace ExtractPkey
{
    class EncryptedPrivateKey
    {
        private const int UkmSize = 8;
        private const int CekSize = 32;
        private const int MacSize = 4;

        private readonly byte[] _ukm;
        private readonly byte[] _cek;
        private readonly byte[] _mac;
        private readonly byte[] _paramset;

        public EncryptedPrivateKey(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException("data");
            
            if (data.Length < 72)
                throw new ArgumentException("Invalid key length.", "data");

            _ukm = new byte[UkmSize];
            _cek = new byte[CekSize];
            _mac = new byte[MacSize];
            _paramset = new byte[9];

            Array.Copy(data, 22, _ukm, 0, UkmSize);
            Array.Copy(data, 34, _cek, 0, CekSize);
            Array.Copy(data, 68, _mac, 0, MacSize);
            Array.Copy(data, 90, _paramset, 0, 9);
        }

        public byte[] UKM { get { return _ukm; } }
        public byte[] CEK { get { return _cek; } }
        public byte[] MAC { get { return _mac; } }

        public DerObjectIdentifier Paramset
        {
            get { return (DerObjectIdentifier)Asn1Object.FromByteArray(_paramset); }
        }

        // https://tools.ietf.org/html/rfc4357#section-6.4
        public byte[] UnwrapKey(byte[] kek)
        {
            var cipher = CipherUtilities.GetCipher("GOST/ECB/NOPADDING");
            var kek_ukm = KEKDiversification(kek, UKM);
            var prms = ParameterUtilities.CreateKeyParameter("GOST", kek_ukm);
            cipher.Init(false, new ParametersWithSBox(prms, Gost28147Engine.GetSBox("E-A")));

            var cekDecrypted = cipher.ProcessBytes(CEK);

            CheckMac(cekDecrypted, kek_ukm);

            return cekDecrypted;
        }

        private void CheckMac(byte[] cekDecrypted, byte[] kek)
        {
            var cekmac = new byte[4];
            var mac = new Gost28147MacIV();
            var key = ParameterUtilities.CreateKeyParameter("GOST", kek);
            var prms = new ParametersWithIV(key, UKM);

            mac.Init(prms);
            mac.BlockUpdate(cekDecrypted, 0, cekDecrypted.Length);
            mac.DoFinal(cekmac, 0);

            for (int i = 0; i < 4; ++i) {
                if (cekmac[i] != MAC[i])
                    throw new CryptographicException("CEK decryption error, MAC values do not match.");
            }
        }

        // https://tools.ietf.org/html/rfc4357#section-6.5
        public static byte[] KEKDiversification(byte[] kek, byte[] ukm)
        {
            var cipher = CipherUtilities.GetCipher("GOST/CFB/NOPADDING");
            var result = (byte[])kek.Clone();
            var S = new byte[8];

            for (int i = 0; i < 8; ++i) {
                int sum1 = 0;
                int sum2 = 0;

                for (int j = 0, mask = 1; j < 8; ++j, mask <<= 1) {
                    var kj = (result[4 * j]) | (result[4 * j + 1] << 8) | (result[4 * j + 2] << 16) | (result[4 * j + 3] << 24);
                    if ((mask & ukm[i]) != 0) {
                        sum1 += kj;
                    } else {
                        sum2 += kj;
                    }
                }

                S[0] = (byte)(sum1 & 0xff);
                S[1] = (byte)((sum1 >> 8) & 0xff);
                S[2] = (byte)((sum1 >> 16) & 0xff);
                S[3] = (byte)((sum1 >> 24) & 0xff);
                S[4] = (byte)(sum2 & 0xff);
                S[5] = (byte)((sum2 >> 8) & 0xff);
                S[6] = (byte)((sum2 >> 16) & 0xff);
                S[7] = (byte)((sum2 >> 24) & 0xff);

                var key = ParameterUtilities.CreateKeyParameter("GOST", result);
                var sbox = new ParametersWithSBox(key, Gost28147Engine.GetSBox("E-A"));
                var prms = new ParametersWithIV(sbox, S);
                cipher.Init(true, prms);
                result = cipher.ProcessBytes(result);
            }

            return result;
        }
    }
}
