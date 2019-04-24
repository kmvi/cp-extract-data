using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace ExtractPkey
{
    class HeaderStructure
    {
        public HeaderStructure(Asn1Sequence seq)
        {
            if (seq?.Count > 0 && seq[0] is Asn1Sequence seq2) {
                foreach (var tag in seq2.OfType<Asn1TaggedObject>()) {
                    switch (tag.TagNo) {
                        case 5:
                            var cert = (tag.GetObject() as Asn1OctetString)?.GetOctets();
                            Certificate = X509CertificateStructure.GetInstance(cert);
                            break;
                        case 6:
                            cert = (tag.GetObject() as Asn1OctetString)?.GetOctets();
                            Certificate2 = X509CertificateStructure.GetInstance(cert);
                            break;
                        case 10:
                            PublicX = Asn1OctetString.GetInstance(tag.GetObject())?.GetOctets();
                            break;
                    }
                }

                var seq3 = seq2?.OfType<Asn1Sequence>().FirstOrDefault();
                PrivateKeyParameters = PrivateKeyParameters.GetInstance(seq3);
                Attributes = seq2?.OfType<DerBitString>().FirstOrDefault();
            }

            if (seq?.Count > 1)
                HMACKey = (seq[1] as Asn1OctetString)?.GetOctets();

            if (HMACKey == null || Attributes == null || PrivateKeyParameters == null || PublicX == null)
                throw new CryptographicException("Ошибка в данных header.key.");
        }

        public byte[] HMACKey { get; }
        public byte[] PublicX { get; }
        public X509CertificateStructure Certificate { get; }
        public X509CertificateStructure Certificate2 { get; }
        public DerBitString Attributes { get; }
        public PrivateKeyParameters PrivateKeyParameters { get; }

        public static HeaderStructure GetInstance(object obj)
        {
            switch (obj) {
                case null:
                    return null;
                case HeaderStructure header:
                    return header;
                case Asn1Sequence seq:
                    return new HeaderStructure(seq);
                default:
                    throw new ArgumentException("Invalid Primary structure.");
            }
        }

        public static HeaderStructure GetInstance(Asn1TaggedObject obj, bool explicitly)
            => GetInstance(Asn1TaggedObject.GetInstance(obj, explicitly));
    }
}
