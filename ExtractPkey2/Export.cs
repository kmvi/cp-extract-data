using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace ExtractPkey
{
    interface IExport
    {
        void Export(Container container, Stream output);
    }

    class PrivateKeyExport : IExport
    {
        public void Export(Container container, Stream output)
        {
            var privateKey = EncodePrivateKey(container);
            var pemObject = new PemObject("PRIVATE KEY", privateKey.GetDerEncoded());
            using (var sw = new StreamWriter(output)) {
                var writer = new PemWriter(sw);
                writer.WriteObject(pemObject);
            }
        }

        private static Asn1Object EncodePrivateKey(Container container)
        {
            return new DerSequence(
                new DerInteger(0),
                new DerSequence(
                    container.SignAlgorithmId,
                    new DerSequence(
                        container.PublicKeyAlg.PublicKeyParamSet,
                        container.PublicKeyAlg.DigestParamSet
                    )
                ),
                new DerOctetString(new DerInteger(container.GetPrivateKey()))
            );
        }
    }

    class CertificateExport : IExport
    {
        public void Export(Container container, Stream output)
        {
            var rawCert = container.GetRawCertificate();
            var pemObject = new PemObject("CERTIFICATE", rawCert);
            using (var sw = new StreamWriter(output)) {
                var writer = new PemWriter(sw);
                writer.WriteObject(pemObject);
            }
        }
    }

    // не работает
    class Pkcs12Export : IExport
    {
        private readonly string _password;

        public Pkcs12Export(string password)
        {
            _password = password;
        }

        public void Export(Container container, Stream output)
        {
            var rawCert = container.GetRawCertificate();
            var privateKey = container.GetPrivateKey();

            var cert = new X509CertificateParser().ReadCertificate(rawCert);
            var certEntry = new X509CertificateEntry(cert);

            string friendlyName = "alias";
            var store = new Pkcs12Store();
            store.SetCertificateEntry(friendlyName, certEntry);
            //store.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(privateKey), new[] { certEntry });

            var password = _password.ToCharArray();
            using (var ms = new MemoryStream()) {
                store.Save(ms, password, new SecureRandom());

                // Save дописывает в конец какой-то мусор
                ms.Position = 0;
                var asn1 = new Asn1InputStream(ms);
                var result = asn1.ReadObject();
                byte[] buf = Pkcs12Utilities.ConvertToDefiniteLength(result.GetEncoded(), password);

                output.Write(buf, 0, buf.Length);
            }
        }
    }
}
