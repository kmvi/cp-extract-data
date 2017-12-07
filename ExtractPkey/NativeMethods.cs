using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace ExtractPkey
{
    static class NativeMethods
    {
        public const uint GR3410_1_MAGIC = 0x3147414D;

        [DllImport("crypt32", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptAcquireCertificatePrivateKey([In] SafeHandle pCert, [In] uint dwFlags, [In] IntPtr pvReserved, [In, Out] ref IntPtr phCryptProv, [In, Out] ref KeySpec pdwKeySpec, [In, Out] ref bool pfCallerFreeProv);

        [Flags]
        public enum KeySpec : uint
        {
            CERT_NCRYPT_KEY_SPEC = 0XFFFFFFFF,
            AT_KEYEXCHANGE = 1,
            AT_SIGNATURE = 2
        }

        [DllImport("crypt32", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CertGetCertificateContextProperty([In] SafeHandle pCertContext, [In] uint dwPropId, [In, Out] IntPtr pvData, [In, Out] ref uint pcbData);
        public const int CERT_KEY_PROV_INFO_PROP_ID = 2;

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptReleaseContext(IntPtr hProv, Int32 dwFlags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int NCryptFreeObject(IntPtr hObject);

        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CertGetCertificateContextProperty([In] IntPtr pCertContext, [In] uint dwPropId, [In, Out] IntPtr pvData, [In, Out] ref uint pcbData);

        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_KEY_PROV_INFO
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszContainerName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszProvName;
            public int dwProvType;
            public int dwFlags;
            public int cProvParam;
            public CRYPT_KEY_PROV_PARAM rgProvParam;
            public int dwKeySpec;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_KEY_PROV_PARAM
        {
            public int dwParam;
            public IntPtr pbData;
            public int cbData;
            public int dwFlags;
        }

        [DllImport("advapi32", SetLastError = true)]
        public static extern bool CryptGetUserKey(IntPtr hProv, uint dwKeySpec, ref IntPtr hKey);

        [DllImport("advapi32", SetLastError = true)]
        public static extern bool CryptDestroyKey(IntPtr phKey);

        [DllImport("advapi32", SetLastError = true)]
        public static extern bool CryptGetKeyParam(
            IntPtr hKey,
            uint dwParam,
            [Out] byte[] pbData,
            [In, Out] ref uint pdwDataLen,
            uint dwFlags);
        public const uint KP_PERMISSIONS = 6;
        public const uint KP_ALGID = 7;
        public const uint CRYPT_EXPORT = 4;

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptGenKey(
                [In] IntPtr hProv,
                [In] ALG_ID Algid,
                [In] uint dwFlags,
                [Out] out IntPtr phKey
            );

        [Flags]
        public enum ALG_ID : uint
        {
            ALG_CLASS_SIGNATURE = 1 << 13,
            ALG_CLASS_KEY_EXCHANGE = 5 << 13, // A000
            ALG_CLASS_DATA_ENCRYPT = 3 << 13, // 6000
            ALG_TYPE_DH = 5 << 9, // A00
            ALG_TYPE_BLOCK = 3 << 9, // 600
            ALG_TYPE_GR3410	= 7 << 9,
            ALG_SID_DH_SANDF = 1,
            ALG_SID_DH_EPHEM = 2,
            ALG_SID_DH_EL_EPHEM = 37,
            ALG_SID_PRO_EXP = 31,
            ALG_SID_GR3410EL = 35,
            CALG_DH_SF = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_SANDF,
            CALG_DH_EPHEM = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_EPHEM,
            CALG_DH_EL_EPHEM = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_EL_EPHEM,
            CALG_PRO_EXPORT = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_PRO_EXP,
            CALG_GR3410EL = ALG_CLASS_SIGNATURE | ALG_TYPE_GR3410 | ALG_SID_GR3410EL,
        }

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptExportKey(IntPtr hKey, IntPtr hExpKey, uint dwBlobType, uint dwFlags, [In, Out] byte[] pbData, ref uint dwDataLen);
        public const uint PUBLICKEYBLOB = 6;
        public const uint PRIVATEKEYBLOB = 7;

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptImportKey(IntPtr hProv, byte[] pbKeyData, UInt32 dwDataLen, IntPtr hPubKey, UInt32 dwFlags, ref IntPtr hKey);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CryptSetKeyParam(
              IntPtr hKey,
              int dwParam,
              byte[] pbData,
              int dwFlags
              );
    }

    struct CRYPT_PUBLICKEYBLOB
    {
        // BLOBHEADER (8 байт)
        public byte bType;
        public byte bVersion;
        public ushort reserved;
        public uint aiKeyAlg;

        // CRYPT_PUBKEYPARAM (8 байт)
        public uint Magic; // NativeMethods.GR3410_1_MAGIC;
        public uint BitLen;

        public uint KeyData1;
        public uint KeyData2;
        public uint KeyData3;
        public uint KeyData4;
        public uint KeyData5;

        public byte[] GetBytes()
        {
            int size = Marshal.SizeOf(this);
            byte[] arr = new byte[size];

            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(this, ptr, true);
            Marshal.Copy(ptr, arr, 0, size);
            Marshal.FreeHGlobal(ptr);

            return arr;
        }
    }
}
