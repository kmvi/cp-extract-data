using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities.Encoders;

namespace ExtractPkey
{
    abstract class PrivateKeyBlob
    {
        public byte[] SessionKey { get; protected set; }

        protected abstract NativeMethods.ALG_ID EphemAlgId { get; }
        protected abstract NativeMethods.ALG_ID ExportAlgId { get; }
        protected abstract NativeMethods.ALG_ID KeyAlgId { get; }
        protected abstract uint PublicKeyLength { get; }
        protected abstract uint BlobLength { get; }
        protected abstract int KeyOffset { get; }

        public byte[] GetPrivateKeyBlob(IntPtr context, KeyDerivation derive)
        {
            bool result, shouldFree = false;
            NativeMethods.KeySpec addInfo = 0;

            IntPtr hProv = IntPtr.Zero, hExportKey = IntPtr.Zero,
                phSessionKey = IntPtr.Zero, userKey = IntPtr.Zero;

            try {
                result = NativeMethods.CryptAcquireCertificatePrivateKey(context, 0, IntPtr.Zero, ref hProv, ref addInfo, ref shouldFree);
                if (!result)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                result = NativeMethods.CryptGetUserKey(hProv, (uint)addInfo, ref userKey);
                if (!result)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                CheckPermission(userKey);

                result = NativeMethods.CryptGenKey(hProv, EphemAlgId, 0, out phSessionKey);
                if (!result)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                uint dhOIDsz = 50;
                var dhOID = new byte[dhOIDsz];
                result = NativeMethods.CryptGetKeyParam(phSessionKey, NativeMethods.KP_DHOID, dhOID, ref dhOIDsz, 0);
                if (!result)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                dhOID = dhOID.Take((int)dhOIDsz - 1).ToArray();
                var dhOIDstr = Encoding.ASCII.GetString(dhOID);

                uint hashOIDsz = 50;
                var hashOID = new byte[hashOIDsz];
                result = NativeMethods.CryptGetKeyParam(phSessionKey, NativeMethods.KP_HASHOID, hashOID, ref hashOIDsz, 0);
                if (!result)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                hashOID = hashOID.Take((int)hashOIDsz - 1).ToArray();
                var hashOIDstr = Encoding.ASCII.GetString(hashOID);

                uint pbdatalen = 0;
                result = NativeMethods.CryptExportKey(phSessionKey, IntPtr.Zero, NativeMethods.PUBLICKEYBLOB, 0, null, ref pbdatalen);
                if (!result)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                SessionKey = new byte[pbdatalen];
                result = NativeMethods.CryptExportKey(phSessionKey, IntPtr.Zero, NativeMethods.PUBLICKEYBLOB, 0, SessionKey, ref pbdatalen);
                if (!result)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                var blob = new CRYPT_PUBLICKEYBLOB {
                    reserved = 0,
                    bType = 6,
                    aiKeyAlg = (uint)KeyAlgId,
                    bVersion = 0x20,
                    Magic = NativeMethods.GR3410_1_MAGIC,
                    BitLen = PublicKeyLength
                };

                var dhOid = new DerObjectIdentifier(dhOIDstr);
                var hashOid = new DerObjectIdentifier(hashOIDstr);
                var seq = new DerSequence(dhOid, hashOid);

                var keyData = seq.GetDerEncoded();
                Array.Resize(ref keyData, 24);

                blob.KeyData1 = BitConverter.ToUInt64(keyData, 0);
                blob.KeyData2 = BitConverter.ToUInt64(keyData, 8);
                blob.KeyData3 = BitConverter.ToUInt64(keyData, 16);

                var blobData = blob.GetBytes();
                var pbdata2 = new byte[BlobLength];
                for (int i = 0; i < KeyOffset; ++i) {
                    pbdata2[i] = blobData[i];
                }

                derive.Init(dhOid, hashOid);
                var genkey = derive.GetPublicKeyBytes();

                for (int i = 0, j = KeyOffset; i < genkey.Length; ++i, ++j) {
                    pbdata2[j] = genkey[i];
                }

                result = NativeMethods.CryptImportKey(hProv, pbdata2, BlobLength, phSessionKey, 0, ref hExportKey);
                if (!result)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                result = NativeMethods.CryptSetKeyParam(hExportKey, (int)NativeMethods.KP_ALGID, BitConverter.GetBytes((uint)ExportAlgId), 0);
                if (!result)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                uint pkSize = 0;
                result = NativeMethods.CryptExportKey(userKey, hExportKey, NativeMethods.PRIVATEKEYBLOB, 0, null, ref pkSize);
                if (!result)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                var ret = new byte[pkSize];
                result = NativeMethods.CryptExportKey(userKey, hExportKey, NativeMethods.PRIVATEKEYBLOB, 0, ret, ref pkSize);
                if (!result)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                return ret;
            } catch (Win32Exception e) {
                throw new CryptographicException(e.Message, e);
            } finally {
                if (shouldFree)
                    NativeMethods.CryptReleaseContext(hProv, 0);

                if (hExportKey != IntPtr.Zero)
                    NativeMethods.CryptDestroyKey(hExportKey);

                if (phSessionKey != IntPtr.Zero)
                    NativeMethods.CryptDestroyKey(phSessionKey);

                if (userKey != IntPtr.Zero)
                    NativeMethods.CryptDestroyKey(userKey);
            }
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
                throw new CryptographicException("Экспорт закрытого ключа не разрешен.");
        }
    }

    class PrivateKeyBlob_2001 : PrivateKeyBlob
    {
        protected override NativeMethods.ALG_ID EphemAlgId => NativeMethods.ALG_ID.CALG_DH_EL_EPHEM;
        protected override NativeMethods.ALG_ID ExportAlgId => NativeMethods.ALG_ID.CALG_PRO_EXPORT;
        protected override NativeMethods.ALG_ID KeyAlgId => NativeMethods.ALG_ID.CALG_GR3410EL;
        protected override uint PublicKeyLength => 512u;
        protected override uint BlobLength => 100;
        protected override int KeyOffset => 36;
    }

    class PrivateKeyBlob_2012_256 : PrivateKeyBlob
    {
        protected override NativeMethods.ALG_ID EphemAlgId => NativeMethods.ALG_ID.CALG_DH_GR3410_12_256_EPHEM;
        protected override NativeMethods.ALG_ID ExportAlgId => NativeMethods.ALG_ID.CALG_PRO12_EXPORT;
        protected override NativeMethods.ALG_ID KeyAlgId => NativeMethods.ALG_ID.CALG_GR3410_12_256;
        protected override uint PublicKeyLength => 512u;
        protected override uint BlobLength => 104;
        protected override int KeyOffset => 37;
    }

    class PrivateKeyBlob_2012_512 : PrivateKeyBlob
    {
        protected override NativeMethods.ALG_ID EphemAlgId => NativeMethods.ALG_ID.CALG_DH_GR3410_12_512_EPHEM;
        protected override NativeMethods.ALG_ID ExportAlgId => NativeMethods.ALG_ID.CALG_PRO12_EXPORT;
        protected override NativeMethods.ALG_ID KeyAlgId => NativeMethods.ALG_ID.CALG_GR3410_12_512;
        protected override uint PublicKeyLength => 1024u;
        protected override uint BlobLength => 168;
        protected override int KeyOffset => 39;
    }
}
