using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ExtractPkey
{
    abstract class SessionKey
    {
        private readonly byte[] _data;

        protected SessionKey(byte[] data)
        {
            _data = new byte[PublicKeyLength];
            Array.Copy(data, Offset, _data, 0, PublicKeyLength);
        }

        protected abstract int PublicKeyLength { get; }
        protected abstract int Offset { get; }
        protected abstract Gost3410PublicKeyAlgParameters PublicKeyAlgParameters { get; }

        public ECPublicKeyParameters GetPublicKey()
        {
            var x = new byte[PublicKeyLength / 2];
            var y = new byte[PublicKeyLength / 2];

            for (int i = 0; i != y.Length; i++) {
                x[i] = _data[PublicKeyLength / 2 - 1 - i];
            }

            for (int i = 0; i != x.Length; i++) {
                y[i] = _data[PublicKeyLength - 1 - i];
            }

            var prms = ECGost3410NamedCurves.GetByOid(PublicKeyAlgParameters.PublicKeyParamSet);
            var point = prms.Curve.ValidatePoint(new BigInteger(1, x), new BigInteger(1, y));

            return new ECPublicKeyParameters("ECGOST3410", point, PublicKeyAlgParameters.PublicKeyParamSet);
        }
    }

    class SessionKey_2001 : SessionKey
    {
        public SessionKey_2001(byte[] data)
            : base(data)
        {
        }

        protected override int PublicKeyLength => 64;
        protected override int Offset => 36;

        protected override Gost3410PublicKeyAlgParameters PublicKeyAlgParameters
            => new Gost3410PublicKeyAlgParameters(
                CryptoProObjectIdentifiers.GostR3410x2001CryptoProXchA,
                CryptoProObjectIdentifiers.GostR3411x94CryptoProParamSet);
    }

    class SessionKey_2012_256 : SessionKey
    {
        public SessionKey_2012_256(byte[] data)
            : base(data)
        {
        }

        protected override int PublicKeyLength => 64;
        protected override int Offset => 37;

        protected override Gost3410PublicKeyAlgParameters PublicKeyAlgParameters
            => new Gost3410PublicKeyAlgParameters(
                CryptoProObjectIdentifiers.GostR3410x2001CryptoProXchA,
                RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256);
    }

    class SessionKey_2012_512 : SessionKey
    {
        public SessionKey_2012_512(byte[] data)
            : base(data)
        {
        }

        protected override int PublicKeyLength => 128;
        protected override int Offset => 39;

        protected override Gost3410PublicKeyAlgParameters PublicKeyAlgParameters
            => new Gost3410PublicKeyAlgParameters(
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetA,
                RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512);
    }
}
