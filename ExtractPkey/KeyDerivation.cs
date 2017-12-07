using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ExtractPkey
{
    class KeyDerivation
    {
        private AsymmetricCipherKeyPair _keyPair;

        public void Init()
        {
            var generator = GeneratorUtilities.GetKeyPairGenerator("ECGOST3410");
            var param = new ECKeyGenerationParameters(CryptoProObjectIdentifiers.GostR3410x2001CryptoProXchA, new SecureRandom());
            generator.Init(param);
            _keyPair = generator.GenerateKeyPair();
        }

        public byte[] GetPublicKeyBytes()
        {
            var result = new byte[64];
            var pubInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_keyPair.Public);
            var encoded = pubInfo.PublicKeyData.GetDerEncoded();
            Array.Copy(encoded, 5, result, 0, 64);
            return result;
        }

        // https://tools.ietf.org/html/rfc4357#section-5.2
        public byte[] Vko(EncryptedPrivateKey encPk, ECPublicKeyParameters sessionKey)
        {
            var privKey = (ECPrivateKeyParameters)_keyPair.Private;

            var ukmBytes = (byte[])encPk.UKM.Clone();
            Array.Reverse(ukmBytes);
            var ukm = new BigInteger(1, ukmBytes);

            var p = ukm.Multiply(privKey.D).Mod(sessionKey.Parameters.Curve.Order);
            var kekPoint = sessionKey.Q.Multiply(p).Normalize();
            var x = kekPoint.XCoord.ToBigInteger().ToByteArrayUnsigned();
            var y = kekPoint.YCoord.ToBigInteger().ToByteArrayUnsigned();

            var kekBytes = new byte[64];
            Array.Copy(y, 0, kekBytes, 0, 32);
            Array.Copy(x, 0, kekBytes, 32, 32);
            Array.Reverse(kekBytes);

            var kek = new byte[32];
            var dig = new Gost3411Digest();
            dig.BlockUpdate(kekBytes, 0, kekBytes.Length);
            dig.DoFinal(kek, 0);

            return kek;
        }
    }
}
