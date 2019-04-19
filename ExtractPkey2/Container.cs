using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace ExtractPkey
{
    abstract class Container
    {
        private readonly Lazy<Asn1Object> _headerObj;
        private readonly Lazy<Data> _data;
        protected readonly string _pin;

        protected Container(string pin)
        {
            _pin = pin;
            _data = new Lazy<Data>(LoadContainerData);
            _headerObj = new Lazy<Asn1Object>(() => Asn1Object.FromByteArray(Header));
        }

        private Asn1Object HeaderObject => _headerObj.Value;

        public byte[] Header => _data.Value.Header;
        public byte[] Masks => _data.Value.Masks;
        public byte[] Masks2 => _data.Value.Masks2;
        public byte[] Name => _data.Value.Name;
        public byte[] Primary => _data.Value.Primary;
        public byte[] Primary2 => _data.Value.Primary2;

        public DerObjectIdentifier PublicKeyParamSetId => GetOID(HeaderObject, "0/2/1/1/0");
        public DerObjectIdentifier DigestAlgorithmId => GetOID(HeaderObject, "0/2/1/1/1");
        public DerObjectIdentifier DHAlgorithmId => GetOID(HeaderObject, "0/2/1/0");
        public ProviderType ProviderType => Asn1Utils.GetProviderType(DHAlgorithmId);
        public DerObjectIdentifier SignAlgorithmId => Asn1Utils.GetSignAlgorithmId(ProviderType);

        public ECPrivateKeyParameters GetPrivateKey()
        {
            var salt = GetSalt();
            var pinArray = Encoding.ASCII.GetBytes(_pin ?? "");

            var decodeKey = GetDecodeKey(salt, pinArray);
            var encodedPrimaryKey = GetPrimaryKey();
            var primKeyWithMask = DecodePrimaryKey(decodeKey, encodedPrimaryKey);

            var masksKey = new BigInteger(1, GetMasksKey());

            var param = new ECKeyGenerationParameters(PublicKeyParamSetId, new SecureRandom());
            var maskInv = masksKey.ModInverse(param.DomainParameters.Curve.Order);
            var rawSecret = primKeyWithMask.Multiply(maskInv).Mod(param.DomainParameters.Curve.Order);

            CheckPublicKey(param.DomainParameters, rawSecret, GetPublicX(HeaderObject));

            return new ECPrivateKeyParameters("ECGOST3410", rawSecret, PublicKeyParamSetId);
        }

        private byte[] GetSalt()
        {
            var masks = Asn1Object.FromByteArray(Masks);

            if (masks is Asn1Sequence masksSeq &&
                masksSeq.Count > 1 &&
                masksSeq[1] is Asn1OctetString saltStr)
            {
                var salt = saltStr.GetOctets();
                if (salt.Length == 12)
                    return salt;
            }

            throw new CryptographicException("Ошибка в данных masks.key.");
        }

        private byte[] GetPrimaryKey()
        {
            var primary = Asn1Object.FromByteArray(Primary);

            if (primary is Asn1Sequence primarySeq &&
                primarySeq.Count > 0 &&
                primarySeq[0] is Asn1OctetString keyStr)
            {
                var key = keyStr.GetOctets();
                if (key.Length == 32 || key.Length == 64)
                    return key;
            }

            throw new CryptographicException("Ошибка в данных primary.key.");
        }

        private byte[] GetMasksKey()
        {
            var masks = Asn1Object.FromByteArray(Masks);

            if (masks is Asn1Sequence masksSeq &&
                masksSeq.Count > 0 &&
                masksSeq[0] is Asn1OctetString keyStr)
            {
                var key = keyStr.GetOctets();
                if (key.Length == 32 || key.Length == 64) {
                    Array.Reverse(key);
                    return key;
                }
            }

            throw new CryptographicException("Ошибка в данных masks.key.");
        }

        private static void CheckPublicKey(ECDomainParameters domainParams, BigInteger privateKey, byte[] publicX)
        {
            var point = domainParams.G.Multiply(privateKey).Normalize();
            var x = point.AffineXCoord.GetEncoded().Reverse().Take(publicX.Length).ToArray();

            if (!publicX.SequenceEqual(x))
                throw new CryptographicException("Не удалось проверить корректность открытого ключа (некорректный ПИН-код?).");
        }

        private static DerObjectIdentifier GetOID(Asn1Object header, string path)
        {
            DerObjectIdentifier algId;
            try {
                algId = Asn1Utils.Goto(header, path) as DerObjectIdentifier;
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
            if (header is Asn1Sequence seq1 &&
                seq1.Count > 0 &&
                seq1[0] is Asn1Sequence seq2)
            {
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

            throw new CryptographicException("Ошибка в данных header.key.");
        }

        public byte[] GetRawCertificate()
        {
            var header = Asn1Object.FromByteArray(Header);
            if (header is Asn1Sequence seq1 && seq1.Count > 0) {
                if (seq1[0] is Asn1Sequence seq2 && seq2.Count >= 6) {
                    return Asn1Utils.ExtractOctets(seq2[4]);
                }
            }

            throw new CryptographicException("Контейнер не содержит сертификата.");
        }

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

        private BigInteger DecodePrimaryKey(byte[] decodeKey, byte[] primaryKey)
        {
            var engine = new Gost28147Engine();

            var sbox =
                ProviderType == ProviderType.CryptoPro_2001
                    ? Gost28147Engine.GetSBox("E-A")
                    : Gost28147_TC26ParamSetZ;

            var param = new ParametersWithSBox(
                new KeyParameter(decodeKey), sbox);

            engine.Init(false, param);

            var buf = new byte[primaryKey.Length];
            for (int i = 0; i < primaryKey.Length; i += 8)
                engine.ProcessBlock(primaryKey, i, buf, i);

            return new BigInteger(1, buf.Reverse().ToArray());
        }

        private static void XorMaterial(byte[] buf36, byte[] buf5c, byte[] src)
        {
            for (int i = 0; i < src.Length; ++i) {
                buf36[i] = (byte)(src[i] ^ 0x36);
                buf5c[i] = (byte)(src[i] ^ 0x5C);
            }
        }

        private byte[] GetDecodeKey(byte[] salt, byte[] pin)
        {
            var pincode4 = new byte[pin.Length * 4];
            for (int i = 0; i < pin.Length; ++i)
                pincode4[i * 4] = pin[i];

            IDigest digest =
                ProviderType == ProviderType.CryptoPro_2001
                    ? new Gost3411Digest(Gost28147Engine.GetSBox("D-A")) as IDigest
                    : new Gost3411_2012_256Digest();

            digest.BlockUpdate(salt, 0, salt.Length);
            if (pin.Length > 0)
                digest.BlockUpdate(pincode4, 0, pincode4.Length);

            var result = new byte[digest.GetDigestSize()];
            digest.DoFinal(result, 0);

            var len = ProviderType == ProviderType.CryptoPro_2001 ? 32 : 64;
            var material36 = new byte[len];
            var material5c = new byte[len];
            var current = new byte[len];

            Array.Copy(Encoding.ASCII.GetBytes("DENEFH028.760246785.IUEFHWUIO.EF"), current, 32);
            
            len = pin.Length > 0 ? 2000 : 2;
            for (int i = 0; i < len; ++i) {
                XorMaterial(material36, material5c, current);
                digest.Reset();
                digest.BlockUpdate(material36, 0, material36.Length);
                digest.BlockUpdate(result, 0, result.Length);
                digest.BlockUpdate(material5c, 0, material5c.Length);
                digest.BlockUpdate(result, 0, result.Length);
                digest.DoFinal(current, 0);
            }

            XorMaterial(material36, material5c, current);
            digest.Reset();
            digest.BlockUpdate(material36, 0, 32);
            digest.BlockUpdate(salt, 0, salt.Length);
            digest.BlockUpdate(material5c, 0, 32);
            if (pin.Length > 0)
                digest.BlockUpdate(pincode4, 0, pincode4.Length);
            digest.DoFinal(current, 0);

            var result_key = new byte[digest.GetDigestSize()];
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
