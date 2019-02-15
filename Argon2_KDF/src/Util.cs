using System;
using System.Text;

namespace Argon2_KDF
{
    public class Util
    {
        public static void Fill(byte[] array, int start, int end, byte value) {
            if (array == null) {
                throw new ArgumentNullException("array");
            }
            if (start < 0 || start >= end) {
                throw new ArgumentOutOfRangeException("start index");
            }
            if (end >= array.Length) {
                throw new ArgumentOutOfRangeException("end index");
            }
            for (int i = start; i < end; i++) {
                array[i] = value;
            }
        }

        public static string BytesToHexString(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", string.Empty);
            //StringBuilder sb = new StringBuilder();
            //foreach (byte b in bytes) {
            //    sb.Append(string.Format("%02x", b & 0xff));
            //}
            //return sb.ToString();
        }

        public static byte[] HexStringToByteArray(string s) {
            int len = s.Length;
            byte[] data = new byte[len / 2];
            for (int i = 0; i < len; i += 2) {
                data[i / 2] = (byte)((Convert.ToInt32(s[i].ToString(), 16) << 4)
                                     + Convert.ToInt32(s[i + 1].ToString(), 16));
            }
            return data;
        }

        public static long LittleEndianBytesToLong(byte[] b) {
            long result = 0;
            for (int i = 7; i >= 0; i--) {
                result <<= 8;
                result |= (b[i] & 0xFF);
            }
            return result;
        }

        public static byte[] IntToLittleEndianBytes(int a) {
            byte[] result = new byte[4];
            result[0] = (byte)(a & 0xFF);
            result[1] = (byte)((a >> 8) & 0xFF);
            result[2] = (byte)((a >> 16) & 0xFF);
            result[3] = (byte)((a >> 24) & 0xFF);
            return result;
        }

        public static byte[] LongToLittleEndianBytes(long a) {
            byte[] result = new byte[8];
            result[0] = (byte)(a & 0xFF);
            result[1] = (byte)((a >> 8) & 0xFF);
            result[2] = (byte)((a >> 16) & 0xFF);
            result[3] = (byte)((a >> 24) & 0xFF);
            result[4] = (byte)((a >> 32) & 0xFF);
            result[5] = (byte)((a >> 40) & 0xFF);
            result[6] = (byte)((a >> 48) & 0xFF);
            result[7] = (byte)((a >> 56) & 0xFF);
            return result;
        }

        public static long IntToLong(int x) {
            byte[] intBytes = IntToLittleEndianBytes(x);
            byte[] bytes = new byte[8];
            Array.Copy(intBytes, 0, bytes, 0, 4);
            return LittleEndianBytesToLong(bytes);
        }
    }
}
