using Mono.Options;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.IO.Pem;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ExtractPkey
{
    class Program
    {
        private static OptionSet options;

        static void Main(string[] args)
        {
            string thumbprint = null;
            bool showHelp = false;

            options = new OptionSet {
                { "t|thumbprint=",  "Отпечаток сертификата", t => thumbprint = t },
                { "h|help", "Помощь", h => showHelp = h != null}
            };

            try {
                options.Parse(args);
            } catch (OptionException e) {
                Console.Error.WriteLine(e.Message);
                return;
            }

            if (showHelp || String.IsNullOrEmpty(thumbprint)) {
                PrintHelp();
                return;
            }

            try {
                var cert = FindCertificate(FixThumbprint(thumbprint));
                var export = new Export(cert);
                var pkey = export.ExportPrivateKey();
                export.CheckPublicKey(pkey);
                PrintPrivateKey(pkey, export.KeyParameters);
            } catch (Exception e) {
                Console.Error.WriteLine(e.Message);
            }
        }

        private static void PrintHelp()
        {
            Console.WriteLine("Использование: extractpkey {ПАРАМЕТРЫ}");
            Console.WriteLine("Извлечение данных из контейнера Крипто ПРО");
            Console.WriteLine();
            Console.WriteLine("Параметры:");
            options.WriteOptionDescriptions(Console.Out);
        }

        private static void PrintPrivateKey(BigInteger pkey, KeyParameters keyParams)
        {
            var gostParams = Gost3410PublicKeyAlgParameters.GetInstance(keyParams.Algorithm.Parameters);

            var pkeyEnc = new DerSequence(
                new DerInteger(0),
                new DerSequence(
                    keyParams.Algorithm.Algorithm,
                    new DerSequence(
                        gostParams.PublicKeyParamSet,
                        gostParams.DigestParamSet
                    )
                ),
                new DerOctetString(new DerInteger(pkey))
            );

            var pemObject = new PemObject("PRIVATE KEY", pkeyEnc.GetDerEncoded());
            using (var sw = new StreamWriter(Console.OpenStandardOutput())) {
                var writer = new PemWriter(sw);
                writer.WriteObject(pemObject);
            }
        }

        private static string FixThumbprint(string thumbprint)
        {
            var result = new StringBuilder();
            foreach (char c in thumbprint) {
                if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
                    result.Append(Char.ToUpperInvariant(c));
            }
            return result.ToString();
        }

        private static X509Certificate2 FindCertificate(string thumbprint)
        {
            var locations = new[] { StoreLocation.LocalMachine, StoreLocation.CurrentUser };
            var names = new[] {
                StoreName.My, StoreName.Root, StoreName.TrustedPeople,
                StoreName.TrustedPublisher, StoreName.AuthRoot
            };

            foreach (var location in locations) {
                foreach (var name in names) {
                    var store = new X509Store(name, location);
                    store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
                    var certs = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
                    if (certs.Count > 0) {
                        return certs[0];
                    }
                }
            }

            throw new CryptographicException($"Сертификат с отпечатком {thumbprint} не найден.");
        }
    }
}
