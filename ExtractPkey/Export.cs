using Microsoft.Win32.SafeHandles;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;
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

        public BigInteger ExportPrivateKey()
        {
            var context = GetHandle(_cert);

            var derive = new KeyDerivation();
            derive.Init();
            
            byte[] sessKey, privKeyBlob;
            ExportPrivateKey(context, derive.GetPublicKeyBytes(), out sessKey, out privKeyBlob);

            _encryptedPkey = new EncryptedPrivateKey(privKeyBlob);
            _sk = new SessionKey(sessKey);
            var kek = derive.Vko(_encryptedPkey, _sk.GetPublicKey());
            var pkey = _encryptedPkey.UnwrapKey(kek);
            Array.Reverse(pkey);

            return new BigInteger(1, pkey);
        }

        public DerObjectIdentifier Paramset { get { return _encryptedPkey.Paramset; } }

        private static void ExportPrivateKey(SafeHandle context, byte[] genkey, out byte[] sessionKeyData, out byte[] privKeyData)
        {
            bool result, shouldFree = false;
            NativeMethods.KeySpec addInfo = 0;

            IntPtr provOrKey = IntPtr.Zero, hExportKey = IntPtr.Zero,
                phSessionKey = IntPtr.Zero, provInfoPtr = IntPtr.Zero, userKey = IntPtr.Zero;            

            try {
                result = NativeMethods.CryptAcquireCertificatePrivateKey(context, 0, IntPtr.Zero, ref provOrKey, ref addInfo, ref shouldFree);
                if (!result)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                uint pcbData = 0;
                result = NativeMethods.CertGetCertificateContextProperty(context, NativeMethods.CERT_KEY_PROV_INFO_PROP_ID, provInfoPtr, ref pcbData);
                if (!result)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                provInfoPtr = Marshal.AllocHGlobal((int)pcbData);
                result = NativeMethods.CertGetCertificateContextProperty(context, NativeMethods.CERT_KEY_PROV_INFO_PROP_ID, provInfoPtr, ref pcbData);
                if (!result)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                var provInfo = (NativeMethods.CRYPT_KEY_PROV_INFO)Marshal.PtrToStructure(provInfoPtr, typeof(NativeMethods.CRYPT_KEY_PROV_INFO));
                result = NativeMethods.CryptGetUserKey(provOrKey, (uint)addInfo, ref userKey);
                if (!result)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                CheckProvider(provInfo);
                CheckPermission(userKey);

                result = NativeMethods.CryptGenKey(provOrKey, NativeMethods.ALG_ID.CALG_DH_EL_EPHEM, 0, out phSessionKey);
                if (!result)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                uint pbdatalen = 0;
                result = NativeMethods.CryptExportKey(phSessionKey, IntPtr.Zero, NativeMethods.PUBLICKEYBLOB, 0, null, ref pbdatalen);
                if (!result)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                sessionKeyData = new byte[pbdatalen];
                result = NativeMethods.CryptExportKey(phSessionKey, IntPtr.Zero, NativeMethods.PUBLICKEYBLOB, 0, sessionKeyData, ref pbdatalen);
                if (!result)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                var blob = new CRYPT_PUBLICKEYBLOB
                {
                    reserved = 0,
                    bType = 6,
                    aiKeyAlg = (uint)NativeMethods.ALG_ID.CALG_GR3410EL,
                    bVersion = 0x20,
                    Magic = NativeMethods.GR3410_1_MAGIC,
                    BitLen = 512,
                    // 301206072a85030202240006072a850302021e01
                    // SEQUENCE(2 elem)
                    // OBJECT IDENTIFIER 1.2.643.2.2.36.0
                    // OBJECT IDENTIFIER1.2.643.2.2.30.1
                    KeyData1 = 0x07061230,
                    KeyData2 = 0x0203852A,
                    KeyData3 = 0x06002402,
                    KeyData4 = 0x03852A07,
                    KeyData5 = 0x011E0202
                };

                var blobData = blob.GetBytes();
                var pbdata2 = new byte[100];
                for (int i = 0; i < blobData.Length; ++i) {
                    pbdata2[i] = blobData[i];
                }

                for (int i = 0, j = 36; i < genkey.Length; ++i, ++j) {
                    pbdata2[j] = genkey[i];
                }
                
                result = NativeMethods.CryptImportKey(provOrKey, pbdata2, pbdatalen, phSessionKey, 0, ref hExportKey);
                if (!result)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                // export wrapped key
                var alg = BitConverter.GetBytes((uint)NativeMethods.ALG_ID.CALG_PRO_EXPORT);
                result = NativeMethods.CryptSetKeyParam(hExportKey, (int)NativeMethods.KP_ALGID, alg, 0);
                if (!result)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                uint pkSize = 0;
                result = NativeMethods.CryptExportKey(userKey, hExportKey, NativeMethods.PRIVATEKEYBLOB, 0, null, ref pkSize);
                if (!result)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                privKeyData = new byte[pkSize];
                result = NativeMethods.CryptExportKey(userKey, hExportKey, NativeMethods.PRIVATEKEYBLOB, 0, privKeyData, ref pkSize);
                if (!result)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            } catch (Win32Exception e) {
                throw new CryptographicException(e.Message, e);
            } finally {
                if (shouldFree)
                    NativeMethods.CryptReleaseContext(provOrKey, 0);

                if (provInfoPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(provInfoPtr);
                
                if (hExportKey != IntPtr.Zero)
                    NativeMethods.CryptDestroyKey(hExportKey);
                
                if (phSessionKey != IntPtr.Zero)
                    NativeMethods.CryptDestroyKey(phSessionKey);
                
                if (userKey != IntPtr.Zero)
                    NativeMethods.CryptDestroyKey(userKey);
            }
        }

        private static void CheckProvider(NativeMethods.CRYPT_KEY_PROV_INFO provInfo)
        {
            var provider = provInfo.pwszProvName.ToUpperInvariant();
            if (!provider.StartsWith("CRYPTO-PRO"))
                throw new CryptographicException("CSP not supported: " + provInfo.pwszProvName);
        }

        /*
        private static X509Certificate2 SelectCertificate()
        {
            var store = new X509Store(StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            var result = X509Certificate2UI.SelectFromCollection(store.Certificates,
                "Select certificate", "Select certificate to export",
                X509SelectionFlag.SingleSelection);
            store.Close();
            return (result != null && result.Count > 0)
                ? result[0]
                : null;
        }
        */

        static SafeHandleZeroOrMinusOneIsInvalid GetHandle(X509Certificate2 cert)
        {
            var contextField = typeof(X509Certificate2).GetField("m_safeCertContext", BindingFlags.Instance | BindingFlags.NonPublic);
            return (SafeHandleZeroOrMinusOneIsInvalid)contextField.GetValue(cert);
        }

        private static void CheckPermission(IntPtr userKey)
        {
            uint datalen = 4;
            var data = new byte[4];

            var result = NativeMethods.CryptGetKeyParam(userKey, NativeMethods.KP_PERMISSIONS, data, ref datalen, 0);
            if (!result)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            var permission = BitConverter.ToUInt32(data, 0);
            if ((permission & NativeMethods.CRYPT_EXPORT) == 0)
                throw new CryptographicException("Private key export disabled.");
        }
    }
}
