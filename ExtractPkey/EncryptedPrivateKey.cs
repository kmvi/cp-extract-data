using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace ExtractPkey
{
    abstract class EncryptedPrivateKey
    {
        private readonly Asn1Object obj;

        private readonly Lazy<byte[]> _ukm;
        private readonly Lazy<byte[]> _cek;
        private readonly Lazy<byte[]> _mac;

        private readonly Lazy<DerObjectIdentifier> _dhAlgId;
        private readonly Lazy<DerObjectIdentifier> _paramSetId;
        private readonly Lazy<DerObjectIdentifier> _digestAlgId;

        public EncryptedPrivateKey(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException("data");
            
            if (data.Length < 72)
                throw new ArgumentException("Invalid key length.", "data");

            obj = Asn1Object.FromByteArray(data.Skip(16).ToArray());

            _ukm = new Lazy<byte[]>(ExtractUkm);
            _cek = new Lazy<byte[]>(ExtractCek);
            _mac = new Lazy<byte[]>(ExtractMac);

            _dhAlgId = new Lazy<DerObjectIdentifier>(ExtractDHAlgorithmId);
            _paramSetId = new Lazy<DerObjectIdentifier>(ExtractParamSetId);
            _digestAlgId = new Lazy<DerObjectIdentifier>(ExtractDigestAlgorithmId);
        }

        private DerObjectIdentifier ExtractDigestAlgorithmId()
        {
            var id = Asn1Utils.Goto(obj, "0/2/1/1/1") as DerObjectIdentifier;
            if (id == null)
                throw new CryptographicException("Unable to extract digest algorithm identifier from private key data.");

            return id;
        }

        private DerObjectIdentifier ExtractParamSetId()
        {
            var id = Asn1Utils.Goto(obj, "0/2/1/1/0") as DerObjectIdentifier;
            if (id == null)
                throw new CryptographicException("Unable to extract paramset identifier from private key data.");

            return id;
        }

        private DerObjectIdentifier ExtractDHAlgorithmId()
        {
            var id = Asn1Utils.Goto(obj, "0/2/1/0") as DerObjectIdentifier;
            if (id == null)
                throw new CryptographicException("Unable to extract DH algorithm identifier from private key data.");

            return id;
        }

        private byte[] ExtractMac()
        {
            var data = (Asn1Utils.Goto(obj, "0/1/1") as Asn1OctetString)?.GetOctets();

            if (data == null)
                throw new CryptographicException("Unable to extract MAC from private key data.");

            if (data.Length != MacSize)
                throw new CryptographicException($"Invalid MAC size: expected {MacSize}, got {data.Length}.");

            return data;
        }

        private byte[] ExtractCek()
        {
            var data = (Asn1Utils.Goto(obj, "0/1/0") as Asn1OctetString)?.GetOctets();

            if (data == null)
                throw new CryptographicException("Unable to extract CEK from private key data.");

            if (data.Length != CekSize)
                throw new CryptographicException($"Invalid CEK size: expected {CekSize}, got {data.Length}.");

            return data;
        }

        private byte[] ExtractUkm()
        {
            var data = (Asn1Utils.Goto(obj, "0/0") as Asn1OctetString)?.GetOctets();

            if (data == null)
                throw new CryptographicException("Unable to extract UKM from private key data.");

            if (data.Length != UkmSize)
                throw new CryptographicException($"Invalid UKM size: expected {UkmSize}, got {data.Length}.");

            return data;
        }

        protected abstract int UkmSize { get; }
        protected abstract int CekSize { get; }
        protected abstract int MacSize { get; }

        protected abstract byte[] Gost28147_SBox { get; }

        public byte[] UKM => _ukm.Value;
        public byte[] CEK => _cek.Value;
        public byte[] MAC => _mac.Value;

        public DerObjectIdentifier ParamSetId => _paramSetId.Value;
        public DerObjectIdentifier DigestAlgorithmId => _digestAlgId.Value;
        public DerObjectIdentifier DHAlgorithmId => _dhAlgId.Value;

        // https://tools.ietf.org/html/rfc4357#section-6.4
        // https://tools.ietf.org/html/rfc7836#section-4.6
        public byte[] UnwrapKey(byte[] kek)
        {
            var cipher = CipherUtilities.GetCipher("GOST/ECB/NOPADDING");
            var kek_ukm = KEKDiversification(kek, UKM);
            var prms = ParameterUtilities.CreateKeyParameter("GOST", kek_ukm);
            cipher.Init(false, new ParametersWithSBox(prms, Gost28147_SBox));

            var cekDecrypted = cipher.ProcessBytes(CEK);

            CheckMac(cekDecrypted, kek_ukm);

            return cekDecrypted;
        }

        protected abstract byte[] KEKDiversification(byte[] kek, byte[] ukm);

        private void CheckMac(byte[] cekDecrypted, byte[] kek)
        {
            var cekmac = new byte[4];
            var mac = new Gost28147Mac();
            var key = ParameterUtilities.CreateKeyParameter("GOST", kek);
            var prms = new ParametersWithIV(key, UKM);

            mac.Init(prms);
            SetSBox(mac, Gost28147_SBox);

            mac.BlockUpdate(cekDecrypted, 0, cekDecrypted.Length);
            mac.DoFinal(cekmac, 0);

            for (int i = 0; i < 4; ++i) {
                if (cekmac[i] != MAC[i])
                    throw new CryptographicException("CEK decryption error, MAC values do not match.");
            }
        }

        private static void SetSBox(Gost28147Mac mac, byte[] sbox)
        {
            var field = mac.GetType().GetField("S", BindingFlags.Instance | BindingFlags.NonPublic);
            var s = (byte[])field.GetValue(mac);
            sbox.CopyTo(s, 0);
        }
    }

    class EncryptedPrivateKey_2001 : EncryptedPrivateKey
    {
        public EncryptedPrivateKey_2001(byte[] data)
            : base(data)
        {
        }

        protected override int UkmSize => 8;
        protected override int CekSize => 32;
        protected override int MacSize => 4;

        protected override byte[] Gost28147_SBox => Gost28147Engine.GetSBox("E-A");

        // https://tools.ietf.org/html/rfc4357#section-6.5
        protected override byte[] KEKDiversification(byte[] kek, byte[] ukm)
        {
            var cipher = CipherUtilities.GetCipher("GOST/CFB/NOPADDING");
            var result = new byte[32];
            Array.Copy(kek, result, 32);
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

    class EncryptedPrivateKey_2012_256 : EncryptedPrivateKey
    {
        private static readonly byte[] Gost28147_TC26ParamSetZ = {
            0xc,0x4,0x6,0x2,0xa,0x5,0xb,0x9,0xe,0x8,0xd,0x7,0x0,0x3,0xf,0x1,
            0x6,0x8,0x2,0x3,0x9,0xa,0x5,0xc,0x1,0xe,0x4,0x7,0xb,0xd,0x0,0xf,
            0xb,0x3,0x5,0x8,0x2,0xf,0xa,0xd,0xe,0x1,0x7,0x4,0xc,0x9,0x6,0x0,
            0xc,0x8,0x2,0x1,0xd,0x4,0xf,0x6,0x7,0x0,0xa,0x5,0x3,0xe,0x9,0xb,
            0x7,0xf,0x5,0xa,0x8,0x1,0x6,0xd,0x0,0x9,0x3,0xe,0xb,0x4,0x2,0xc,
            0x5,0xd,0xf,0x6,0x9,0x2,0xc,0xa,0xb,0x7,0x8,0x1,0x4,0x3,0xe,0x0,
            0x8,0xe,0x2,0x5,0x6,0x9,0x1,0xc,0xf,0x4,0xb,0x0,0xd,0xa,0x3,0x7,
            0x1,0x7,0xe,0xd,0x0,0x5,0x8,0x3,0x4,0xf,0xa,0x6,0x9,0xc,0xb,0x2,
        };

        public EncryptedPrivateKey_2012_256(byte[] data)
            : base(data)
        {
        }

        protected override int UkmSize => 8;
        protected override int CekSize => 32;
        protected override int MacSize => 4;

        protected override byte[] Gost28147_SBox => Gost28147_TC26ParamSetZ;

        protected override byte[] KEKDiversification(byte[] kek, byte[] ukm)
            => KDF_GOSTR3411_2012_256(kek, new byte[] { 0x26, 0xBD, 0xB8, 0x78 }, ukm);

        // https://tools.ietf.org/html/rfc7836#section-4.5
        protected static byte[] KDF_GOSTR3411_2012_256(byte[] k_in, byte[] label, byte[] seed)
        {
            var data = new byte[label.Length + seed.Length + 4];
            Array.Copy(label, 0, data, 1, label.Length);
            Array.Copy(seed, 0, data, label.Length + 2, seed.Length);
            data[0] = 1;
            data[data.Length - 2] = 1;

            var mac = MacUtilities.GetMac(RosstandartObjectIdentifiers.id_tc26_hmac_gost_3411_12_256);
            mac.Init(new KeyParameter(k_in));

            mac.BlockUpdate(data, 0, data.Length);

            var result = new byte[mac.GetMacSize()];
            mac.DoFinal(result, 0);

            return result;
        }

        // https://tc26.ru/standard/rs/%D0%A0%2050.1.111-2016.pdf
        protected static byte[] PBKDF2(byte[] p, byte[] s, int c, int dkLen)
        {
            int n = dkLen / 64;
            var u = new byte[c][];
            var t = new byte[n][];
            var hmac = MacUtilities.GetMac(RosstandartObjectIdentifiers.id_tc26_hmac_gost_3411_12_512);
            int sz = hmac.GetMacSize();
            for (int i = 0; i < n; ++i) {
                for (int j = 0; j < c; ++j) {
                    u[j] = new byte[sz];
                    var data = j == 0 ? s.Concat(BitConverter.GetBytes(i + 1).Reverse()).ToArray() : u[j - 1];
                    hmac.Reset();
                    hmac.Init(new KeyParameter(p));
                    hmac.BlockUpdate(data, 0, data.Length);
                    hmac.DoFinal(u[j], 0);
                }
                t[i] = new byte[sz];
                Array.Copy(u[0], t[i], sz);
                for (int j = 1; j < c; ++j) {
                    for (int k = 0; k < sz; ++k)
                        t[i][k] ^= u[j][k];
                }
            }

            var result = new byte[dkLen];
            for (int i = 0, j = 0; i < dkLen; ++i) {
                result[i] = t[j][i % sz];
                if (i % sz == sz - 1)
                    j++;
            }

            return result;
        }
    }

    class EncryptedPrivateKey_2012_512 : EncryptedPrivateKey_2012_256
    {
        public EncryptedPrivateKey_2012_512(byte[] data)
            : base(data)
        {
        }

        protected override int UkmSize => 8;
        protected override int CekSize => 64;
        protected override int MacSize => 4;
    }
}
