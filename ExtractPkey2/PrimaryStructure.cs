using Org.BouncyCastle.Asn1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace ExtractPkey
{
    class PrimaryStructure
    {
        public PrimaryStructure(Asn1Sequence seq)
        {
            if (seq?.Count > 0)
                Key = (seq[0] as Asn1OctetString)?.GetOctets();

            if (seq?.Count > 1)
                SecondaryKey = (seq[1] as Asn1OctetString)?.GetOctets();

            if (seq?.Count > 2)
                HMACKey = (seq[2] as Asn1OctetString)?.GetOctets();

            if (Key == null)
                throw new CryptographicException("Ошибка в данных primary.key.");
        }

        public byte[] Key { get; }
        public byte[] SecondaryKey { get; }
        public byte[] HMACKey { get; }

        public static PrimaryStructure GetInstance(object obj)
        {
            switch (obj) {
                case null:
                    return null;
                case PrimaryStructure primary:
                    return primary;
                case Asn1Sequence seq:
                    return new PrimaryStructure(seq);
                default:
                    throw new ArgumentException($"Неподдерживаемый тип: {obj.GetType().Name}");
            }
        }

        public static PrimaryStructure GetInstance(Asn1TaggedObject obj, bool explicitly)
            => GetInstance(Asn1TaggedObject.GetInstance(obj, explicitly));
    }
}
