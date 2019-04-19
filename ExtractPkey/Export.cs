using Microsoft.Win32.SafeHandles;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ExtractPkey
{
    class Export
    {
        private readonly X509Certificate2 _cert;
        private EncryptedPrivateKey _encryptedPkey;
        private SessionKey _sk;

        public Export(X509Certificate2 certificate)
        {
            _cert = certificate;
        }

        private static CspParameters GetPrivateKeyInfo(X509Certificate2 cert)
        {
            var handle = typeof(X509Certificate2).GetField("m_safeCertContext",
                BindingFlags.Instance | BindingFlags.NonPublic);
            var method = typeof(X509Certificate2).GetMethod("GetPrivateKeyInfo",
                BindingFlags.Static | BindingFlags.NonPublic);
            var result = new CspParameters();
            method.Invoke(null, new object[] { handle.GetValue(cert), result });
            return result;
        }

        public BigInteger ExportPrivateKey()
        {
            var pkeyInfo = GetPrivateKeyInfo(_cert);
            CheckProvider(pkeyInfo);
            var provType = (ProviderType)pkeyInfo.ProviderType;
            var factory = KeyExportFactory.Create(provType);

            GetPrivateKeyInfo(_cert);

            var derive = factory.CreateKeyDerivation();
            derive.Init();

            var blob = factory.CreatePrivateKeyBlob();
            var privKeyBlob = blob.GetPrivateKeyBlob(_cert.Handle, derive.GetPublicKeyBytes());
            
            _encryptedPkey = factory.CreateEncryptedPrivateKey(privKeyBlob);
            _sk = factory.CreateSessionKey(blob.SessionKey);
            var kek = derive.Vko(_encryptedPkey, _sk.GetPublicKey());
            var pkey = _encryptedPkey.UnwrapKey(kek);
            Array.Reverse(pkey);

            return new BigInteger(1, pkey);
        }

        public DerObjectIdentifier ParamSetId => _encryptedPkey.ParamSetId;
        public DerObjectIdentifier DHAlgorithmId => _encryptedPkey.DHAlgorithmId;
        public DerObjectIdentifier DigestAlgorithmId => _encryptedPkey.DigestAlgorithmId;

        public void CheckPublicKey(BigInteger privateKey)
        {
            var param = new ECKeyGenerationParameters(ParamSetId, new SecureRandom());
            var point = param.DomainParameters.G.Multiply(privateKey).Normalize();
            var x = point.AffineXCoord.GetEncoded().Reverse().ToArray();
            var publicKey = _cert.GetPublicKey();
            for (int i = 0; i < x.Length; ++i) {
                if (x[i] != publicKey[i + publicKey.Length - x.Length * 2])
                    throw new CryptographicException("Public key check failed.");
            }
        }

        private static void CheckProvider(CspParameters cspParams)
        { 
            if (cspParams.ProviderType != 75 && cspParams.ProviderType != 80 && cspParams.ProviderType != 81) {
                throw new CryptographicException($"CSP not supported: {cspParams.ProviderName}");
            }
        }
    }
}
