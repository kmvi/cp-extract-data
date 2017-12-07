using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ExtractPkey
{
    class SessionKey
    {
        private const int PublicKeyLength = 64;

        private readonly byte[] _data;

        public SessionKey(byte[] data)
        {
            _data = new byte[PublicKeyLength];
            Array.Copy(data, 36, _data, 0, PublicKeyLength);
        }

        public ECPublicKeyParameters GetPublicKey()
        {
            var gostprm = new Gost3410PublicKeyAlgParameters(
                CryptoProObjectIdentifiers.GostR3410x2001CryptoProXchA,
                CryptoProObjectIdentifiers.GostR3411x94CryptoProParamSet);

            var x = new byte[PublicKeyLength / 2];
            var y = new byte[PublicKeyLength / 2];

            for (int i = 0; i != y.Length; i++) {
                x[i] = _data[PublicKeyLength / 2 - 1 - i];
            }

            for (int i = 0; i != x.Length; i++) {
                y[i] = _data[PublicKeyLength - 1 - i];
            }

            var prms = ECGost3410NamedCurves.GetByOid(gostprm.PublicKeyParamSet);
            var point = prms.Curve.ValidatePoint(new BigInteger(1, x), new BigInteger(1, y));

            return new ECPublicKeyParameters("ECGOST3410", point, gostprm.PublicKeyParamSet);
        }
    }
}
