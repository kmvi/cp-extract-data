using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace ExtractCert
{
    abstract class Container
    {
        private readonly Lazy<Data> _data;
        protected readonly string _pin;

        protected Container(string pin)
        {
            _pin = pin;
            _data = new Lazy<Data>(LoadContainerData);
        }

        public byte[] Header { get { return _data.Value.Header; } }
        public byte[] Masks { get { return _data.Value.Masks; } }
        public byte[] Masks2 { get { return _data.Value.Masks2; } }
        public byte[] Name { get { return _data.Value.Name; } }
        public byte[] Primary { get { return _data.Value.Primary; } }
        public byte[] Primary2 { get { return _data.Value.Primary2; } }

        public ECPrivateKeyParameters GetPrivateKey()
        {
            var salt = GetSalt();
            var pinArray = Encoding.ASCII.GetBytes(_pin ?? "");
            var decodeKey = GetDecodeKey(salt, pinArray);

            var encodedPrimaryKey = GetPrimaryKey();
            var primKeyWithMask = DecodePrimaryKey(decodeKey, encodedPrimaryKey);

            var masksKey = new BigInteger(1, GetMasksKey());

            var header = Asn1Object.FromByteArray(Header);
            var algId = GetAlgorithmId(header);

            var param = new ECKeyGenerationParameters(algId, new SecureRandom());
            var maskInv = masksKey.ModInverse(param.DomainParameters.Curve.Order);
            var rawSecret = primKeyWithMask.Multiply(maskInv).Mod(param.DomainParameters.Curve.Order);

            CheckPublicKey(param.DomainParameters, rawSecret, GetPublicX(header));

            return new ECPrivateKeyParameters("ECGOST3410", rawSecret, algId);
        }

        private byte[] GetSalt()
        {
            var data = Masks.Skip(38).Take(12).ToArray();
            if (data.Length != 12)
                throw new CryptographicException("Ошибка в данных masks.key.");
            return data;
        }

        private byte[] GetPrimaryKey()
        {
            var data = Primary.Skip(4).Take(32).ToArray();
            if (data.Length != 32)
                throw new CryptographicException("Ошибка в данных primary.key.");
            return data;
        }

        private byte[] GetMasksKey()
        {
            var data = Masks.Skip(4).Take(32).Reverse().ToArray();
            if (data.Length != 32)
                throw new CryptographicException("Ошибка в данных masks.key.");
            return data;
        }

        private static void CheckPublicKey(ECDomainParameters domainParams, BigInteger privateKey, byte[] publicX)
        {
            var point = domainParams.G.Multiply(privateKey).Normalize();
            var x = point.AffineXCoord.GetEncoded().Reverse().Take(8).ToArray();

            if (!publicX.SequenceEqual(x))
                throw new CryptographicException("Не удалось проверить корректность открытого ключа (некорректный ПИН-код?).");
        }

        private static DerObjectIdentifier GetAlgorithmId(Asn1Object header)
        {
            DerObjectIdentifier algId;
            try {
                algId = Asn1Utils.Goto(header, "0/2/1/1/0") as DerObjectIdentifier;
            } catch (Asn1Exception e) {
                throw new CryptographicException("Ошибка в данных header.key.", e);
            }

            if (algId != null) {
                return algId;
            }

            throw new CryptographicException("Ошибка в данных header.key.");
        }

        private static byte[] GetPublicX(Asn1Object header)
        {
            var seq1 = header as Asn1Sequence;
            if (seq1 != null && seq1.Count > 0) {
                var seq2 = seq1[0] as Asn1Sequence;
                if (seq2 != null) {
                    byte[] key = null;
                    if (seq2.Count == 5 || seq2.Count == 6) {
                        key = Asn1Utils.ExtractOctets(seq2[seq2.Count - 1]);
                    } else if (seq2.Count == 7) {
                        key = Asn1Utils.ExtractOctets(seq2[5]);
                    }
                    if (key != null && key.Length == 8) {
                        return key;
                    }
                }
            }

            throw new CryptographicException("Ошибка в данных header.key.");
        }

        public byte[] GetRawCertificate()
        {
            var header = Asn1Object.FromByteArray(Header);
            var seq1 = header as Asn1Sequence;
            if (seq1 != null && seq1.Count > 0) {
                var seq2 = seq1[0] as Asn1Sequence;
                if (seq2 != null && seq2.Count == 6) {
                    return Asn1Utils.ExtractOctets(seq2[4]);
                }
            }

            throw new CryptographicException("Контейнер не содержит сертификата.");
        }

        private BigInteger DecodePrimaryKey(byte[] decodeKey, byte[] primaryKey)
        {
            var engine = new Gost28147Engine();
            var param = new ParametersWithSBox(
                new KeyParameter(decodeKey),
                Gost28147Engine.GetSBox("E-A"));

            engine.Init(false, param);

            var buf = new byte[32];
            engine.ProcessBlock(primaryKey, 0, buf, 0);
            engine.ProcessBlock(primaryKey, 8, buf, 8);
            engine.ProcessBlock(primaryKey, 16, buf, 16);
            engine.ProcessBlock(primaryKey, 24, buf, 24);

            return new BigInteger(1, buf.Reverse().ToArray());
        }

        private static void XorMaterial(byte[] buf36, byte[] buf5c, byte[] src)
        {
            for (int i = 0; i < 32; ++i) {
                buf36[i] = (byte)(src[i] ^ 0x36);
                buf5c[i] = (byte)(src[i] ^ 0x5C);
            }
        }

        private byte[] GetDecodeKey(byte[] salt, byte[] pin)
        {
            var pincode4 = new byte[pin.Length * 4];
            for (int i = 0; i < pin.Length; ++i)
                pincode4[i * 4] = pin[i];

            var digest = new Gost3411Digest(Gost28147Engine.GetSBox("D-A"));
            digest.BlockUpdate(salt, 0, salt.Length);
            if (pin.Length > 0)
                digest.BlockUpdate(pincode4, 0, pincode4.Length);

            var result = new byte[32];
            digest.DoFinal(result, 0);

            var current = Encoding.ASCII.GetBytes("DENEFH028.760246785.IUEFHWUIO.EF");
            var material36 = new byte[32];
            var material5c = new byte[32];
            int len = pin.Length > 0 ? 2000 : 2;
            for (int i = 0; i < len; ++i) {
                XorMaterial(material36, material5c, current);
                digest.Reset();
                digest.BlockUpdate(material36, 0, 32);
                digest.BlockUpdate(result, 0, 32);
                digest.BlockUpdate(material5c, 0, 32);
                digest.BlockUpdate(result, 0, 32);
                digest.DoFinal(current, 0);
            }

            XorMaterial(material36, material5c, current);
            digest.Reset();
            digest.BlockUpdate(material36, 0, 32);
            digest.BlockUpdate(salt, 0, 12);
            digest.BlockUpdate(material5c, 0, 32);
            if (pin.Length > 0)
                digest.BlockUpdate(pincode4, 0, pincode4.Length);
            digest.DoFinal(current, 0);

            var result_key = new byte[32];
            digest.Reset();
            digest.BlockUpdate(current, 0, 32);
            digest.DoFinal(result_key, 0);

            return result_key;
        }

        protected abstract Data LoadContainerData();

        protected class Data
        {
            public byte[] Header { get; set; }
            public byte[] Masks { get; set; }
            public byte[] Masks2 { get; set; }
            public byte[] Name { get; set; }
            public byte[] Primary { get; set; }
            public byte[] Primary2 { get; set; }
        }
    }
}
