using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ExtractPkey
{
    abstract class KeyDerivation
    {
        protected AsymmetricCipherKeyPair _keyPair;

        protected abstract int PublicKeyLength { get; }
        protected abstract IDigest GetDigest();

        public void Init(DerObjectIdentifier publicKeyParamSetOid, DerObjectIdentifier digestParamSetOid)
        {
            var curve = ECGost3410NamedCurves.GetByOid(publicKeyParamSetOid);
            var ecp = new ECNamedDomainParameters(publicKeyParamSetOid, curve);
            var gostParams = new ECGost3410Parameters(ecp, publicKeyParamSetOid, digestParamSetOid, null);
            var param = new ECKeyGenerationParameters(gostParams, new SecureRandom());
            var generator = new ECKeyPairGenerator();
            generator.Init(param);
            _keyPair = generator.GenerateKeyPair();
        }

        public byte[] GetPublicKeyBytes()
        {
            var result = new byte[PublicKeyLength];
            var pubInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_keyPair.Public);
            var encoded = pubInfo.PublicKeyData.GetBytes();
            Array.Copy(encoded, encoded.Length - PublicKeyLength, result, 0, PublicKeyLength);
            return result;
        }

        // https://tools.ietf.org/html/rfc4357#section-5.2
        // https://tools.ietf.org/html/rfc7836#section-4.3
        public byte[] Vko(EncryptedPrivateKey encPk, ECPublicKeyParameters y)
        {
            var x = (ECPrivateKeyParameters)_keyPair.Private;

            var ukmBytes = (byte[])encPk.UKM.Clone();
            Array.Reverse(ukmBytes);
            var ukm = new BigInteger(1, ukmBytes);

            var p = ukm.Multiply(x.D).Mod(y.Parameters.Curve.Order);
            var kekPoint = y.Q.Multiply(p).Normalize();
            var kekPointX = kekPoint.AffineXCoord.ToBigInteger().ToByteArrayUnsigned();
            var kekPointY = kekPoint.AffineYCoord.ToBigInteger().ToByteArrayUnsigned();

            var kekBytes = new byte[kekPointX.Length + kekPointY.Length];
            Array.Copy(kekPointY, 0, kekBytes, 0, kekPointY.Length);
            Array.Copy(kekPointX, 0, kekBytes, kekPointY.Length, kekPointX.Length);
            Array.Reverse(kekBytes);

            var dig = GetDigest();
            var kek = new byte[dig.GetDigestSize()];            
            dig.BlockUpdate(kekBytes, 0, kekBytes.Length);
            dig.DoFinal(kek, 0);

            return kek;
        }
    }

    class KeyDerivation_2001 : KeyDerivation
    {
        protected override int PublicKeyLength => 64;
        protected override IDigest GetDigest() => new Gost3411Digest();
    }

    class KeyDerivation_2012_256 : KeyDerivation
    {
        protected override int PublicKeyLength => 64;
        protected override IDigest GetDigest() => new Gost3411_2012_256Digest();
    }

    class KeyDerivation_2012_512 : KeyDerivation
    {
        protected override int PublicKeyLength => 128;
        protected override IDigest GetDigest() => new Gost3411_2012_256Digest();
    }
}
