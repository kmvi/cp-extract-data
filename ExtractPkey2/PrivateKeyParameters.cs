using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace ExtractPkey
{
    class PrivateKeyParameters
    {
        public PrivateKeyParameters(Asn1Sequence seq)
        {
            Attributes = seq?.OfType<DerBitString>().FirstOrDefault();
            Algorithm = seq?.OfType<Asn1TaggedObject>()
                .Where(x => x.TagNo == 0)
                .Select(x => AlgorithmIdentifier.GetInstance(x, false))
                .FirstOrDefault();

            if (Algorithm == null)
                throw new CryptographicException("Ошибка в данных header.key.");
        }

        public DerBitString Attributes { get; }
        public AlgorithmIdentifier Algorithm { get; }

        public static PrivateKeyParameters GetInstance(object obj)
        {
            switch (obj) {
                case null:
                    return null;
                case PrivateKeyParameters pkp:
                    return pkp;
                case Asn1Sequence seq:
                    return new PrivateKeyParameters(seq);
                default:
                    throw new ArgumentException("Invalid PrivateKeyParameters structure.");
            }
        }

        public static PrivateKeyParameters GetInstance(Asn1TaggedObject obj, bool explicitly)
            => GetInstance(Asn1TaggedObject.GetInstance(obj, explicitly));
    }
}
