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
        private readonly Lazy<HeaderStructure> _headerObj;
        private readonly Lazy<PrimaryStructure> _primaryObj;
        private readonly Lazy<MasksStructure> _masksObj;
        private readonly Lazy<Data> _data;
        protected readonly string _pin;

        protected Container(string pin)
        {
            _pin = pin;
            _data = new Lazy<Data>(LoadContainerData);
            _headerObj = new Lazy<HeaderStructure>(LoadHeader);
            _primaryObj = new Lazy<PrimaryStructure>(LoadPrimary);
            _masksObj = new Lazy<MasksStructure>(LoadMasks);
        }

        private MasksStructure LoadMasks()
            => MasksStructure.GetInstance(Asn1Object.FromByteArray(_data.Value.Masks));

        private PrimaryStructure LoadPrimary()
            => PrimaryStructure.GetInstance(Asn1Object.FromByteArray(_data.Value.Primary));

        private HeaderStructure LoadHeader()
            => HeaderStructure.GetInstance(Asn1Object.FromByteArray(_data.Value.Header));

        public HeaderStructure Header => _headerObj.Value;
        public PrimaryStructure Primary => _primaryObj.Value;
        public MasksStructure Masks => _masksObj.Value;

        public Gost3410PublicKeyAlgParameters PublicKeyAlg
            => Gost3410PublicKeyAlgParameters.GetInstance(Header.PrivateKeyParameters.Algorithm.Parameters);

        public DerObjectIdentifier DHAlgorithmId
            => Header.PrivateKeyParameters.Algorithm.Algorithm;

        public ProviderType ProviderType
            => Asn1Utils.GetProviderType(DHAlgorithmId);

        public DerObjectIdentifier SignAlgorithmId
            => Asn1Utils.GetSignAlgorithmId(ProviderType);


        public ECPrivateKeyParameters GetPrivateKey()
        {
            var pinArray = Encoding.ASCII.GetBytes(_pin ?? "");
            var decodeKey = GetDecodeKey(Masks.Salt, pinArray);
            var primKeyWithMask = DecodePrimaryKey(decodeKey, Primary.Key);

            var masksKey = new BigInteger(1, Masks.Key);
            var param = new ECKeyGenerationParameters(PublicKeyAlg.PublicKeyParamSet, new SecureRandom());
            var maskInv = masksKey.ModInverse(param.DomainParameters.Curve.Order);
            var rawSecret = primKeyWithMask.Multiply(maskInv).Mod(param.DomainParameters.Curve.Order);

            CheckPublicKey(param.DomainParameters, rawSecret, Header.PublicX);

            return new ECPrivateKeyParameters("ECGOST3410", rawSecret, param.PublicKeyParamSet);
        }

        private static void CheckPublicKey(ECDomainParameters domainParams, BigInteger privateKey, byte[] publicX)
        {
            var point = domainParams.G.Multiply(privateKey).Normalize();
            var x = point.AffineXCoord.GetEncoded().Reverse().Take(publicX.Length).ToArray();

            if (!publicX.SequenceEqual(x))
                throw new CryptographicException("Не удалось проверить корректность открытого ключа (некорректный ПИН-код?).");
        }

        public byte[] GetRawCertificate()
        {
            if (Header.Certificate != null)
                return Header.Certificate.GetEncoded();

            if (Header.Certificate2 != null)
                return Header.Certificate2.GetEncoded();

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
