using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Rosstandart;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace ExtractPkey
{
    static class Asn1Utils
    {
        public static Asn1Encodable Goto(Asn1Encodable obj, string path)
        {
            Asn1Encodable cur = obj;
            string[] parts = path.Split('/');
            
            foreach (string part in parts) {
                var seq = cur as Asn1Sequence;
                if (seq == null && cur is Asn1TaggedObject tag) {
                    seq = tag.GetObject() as Asn1Sequence;
                }

                int index = Int32.Parse(part);
                if (seq != null && index >= 0 && seq.Count > index) {
                    cur = seq[index];
                } else {
                    throw new Asn1Exception(String.Format(
                        "Невозможно выполнить переход по индексу {0} в объекте {1}.", index, cur));
                }
            }

            return cur;
        }

        public static byte[] ExtractOctets(Asn1Encodable obj)
            => (obj is Asn1TaggedObject tagObj && tagObj.GetObject() is Asn1OctetString str)
                    ? str.GetOctets()
                    : new byte[0];

        private static readonly DerObjectIdentifier GostR3410_2001DH =
            new DerObjectIdentifier(CryptoProObjectIdentifiers.GostID + ".98");

        public static ProviderType GetProviderType(DerObjectIdentifier algId)
        {
            if (algId.Equals(GostR3410_2001DH))
                return ProviderType.CryptoPro_2001;
            else if (algId.Equals(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_256))
                return ProviderType.CryptoPro_2012_256;
            else if (algId.Equals(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_512))
                return ProviderType.CryptoPro_2012_512;

            throw new CryptographicException($"Неподдерживаемый OID: {algId}.");
        }

        public static DerObjectIdentifier GetSignAlgorithmId(ProviderType provider)
        {
            switch (provider) {
                case ProviderType.CryptoPro_2001:
                    return CryptoProObjectIdentifiers.GostR3410x2001;
                case ProviderType.CryptoPro_2012_256:
                    return RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256;
                case ProviderType.CryptoPro_2012_512:
                    return RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512;
                default:
                    throw new CryptographicException($"Неподдерживаемый криптопровайдер: {provider}.");
            }
        }
    }
}
