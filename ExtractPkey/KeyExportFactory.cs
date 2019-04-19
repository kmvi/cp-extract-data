using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ExtractPkey
{
    abstract class KeyExportFactory
    {
        public abstract KeyDerivation CreateKeyDerivation();
        public abstract SessionKey CreateSessionKey(byte[] keyData);
        public abstract EncryptedPrivateKey CreateEncryptedPrivateKey(byte[] blob);
        public abstract PrivateKeyBlob CreatePrivateKeyBlob();

        public static KeyExportFactory Create(ProviderType provider)
        {
            switch (provider) {
                case ProviderType.CryptoPro_2001:
                    return new KeyExportFactory_2001();
                case ProviderType.CryptoPro_2012_512:
                    return new KeyExportFactory_2012_256();
                case ProviderType.CryptoPro_2012_1024:
                    return new KeyExportFactory_2012_512();
                default:
                    throw new ArgumentOutOfRangeException(nameof(provider), $"Provider not supported: {provider}");
            }
        }

        class KeyExportFactory_2001 : KeyExportFactory
        {
            public override KeyDerivation CreateKeyDerivation()
                => new KeyDerivation_2001();

            public override SessionKey CreateSessionKey(byte[] keyData)
                => new SessionKey_2001(keyData);

            public override EncryptedPrivateKey CreateEncryptedPrivateKey(byte[] blob)
                => new EncryptedPrivateKey_2001(blob);

            public override PrivateKeyBlob CreatePrivateKeyBlob()
                => new PrivateKeyBlob_2001();
        }

        class KeyExportFactory_2012_256 : KeyExportFactory
        {
            public override KeyDerivation CreateKeyDerivation()
                => new KeyDerivation_2012_256();

            public override SessionKey CreateSessionKey(byte[] keyData)
                => new SessionKey_2012_256(keyData);

            public override EncryptedPrivateKey CreateEncryptedPrivateKey(byte[] blob)
                => new EncryptedPrivateKey_2012_256(blob);

            public override PrivateKeyBlob CreatePrivateKeyBlob()
                => new PrivateKeyBlob_2012_256();
        }

        class KeyExportFactory_2012_512 : KeyExportFactory
        {
            public override KeyDerivation CreateKeyDerivation()
                => new KeyDerivation_2012_512();

            public override SessionKey CreateSessionKey(byte[] keyData)
                => new SessionKey_2012_512(keyData);

            public override EncryptedPrivateKey CreateEncryptedPrivateKey(byte[] blob)
                => new EncryptedPrivateKey_2012_512(blob);

            public override PrivateKeyBlob CreatePrivateKeyBlob()
                => new PrivateKeyBlob_2012_512();
        }
    }
}
