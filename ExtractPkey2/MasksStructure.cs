using Org.BouncyCastle.Asn1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace ExtractPkey
{
    class MasksStructure
    {
        public MasksStructure(Asn1Sequence seq)
        {
            if (seq?.Count > 2) {
                Key = (seq[0] as Asn1OctetString)?.GetOctets();
                Salt = (seq[1] as Asn1OctetString)?.GetOctets();
                HMAC = (seq[2] as Asn1OctetString)?.GetOctets();
            }

            if (Key == null || Salt == null || HMAC == null)
                throw new CryptographicException("Ошибка в данных masks.key.");

            Array.Reverse(Key);
        }

        public byte[] Key { get; }
        public byte[] Salt { get; }
        public byte[] HMAC { get; }

        public static MasksStructure GetInstance(object obj)
        {
            switch (obj) {
                case null:
                    return null;
                case MasksStructure masks:
                    return masks;
                case Asn1Sequence seq:
                    return new MasksStructure(seq);
                default:
                    throw new ArgumentException("Invalid Masks structure.");
            }
        }

        public static MasksStructure GetInstance(Asn1TaggedObject obj, bool explicitly)
            => GetInstance(Asn1TaggedObject.GetInstance(obj, explicitly));
    }
}
