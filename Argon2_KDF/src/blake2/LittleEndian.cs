using System.Text;

namespace Argon2_KDF.blake2
{
    // ---------------------------------------------------------------------
    // Little Endian Codecs (inlined in the compressor)
    /*
     * impl note: these are not library funcs and used in hot loops, so no
     * null or bounds checks are performed. For our purposes, this is OK.
     */
    // ---------------------------------------------------------------------
    public class LittleEndian
    {
        private static readonly byte[] hex_digits = new byte[] { (byte)'0', (byte)'1', (byte)'2', (byte)'3',
                                                                 (byte)'4', (byte)'5', (byte)'6', (byte)'7',
                                                                 (byte)'8', (byte)'9', (byte)'a', (byte)'b',
                                                                 (byte)'c', (byte)'d', (byte)'e', (byte)'f' };

        private static byte[] HEX_digits = new byte[] { (byte)'0', (byte)'1', (byte)'2', (byte)'3',
                                                        (byte)'4', (byte)'5', (byte)'6', (byte)'7',
                                                        (byte)'8', (byte)'9', (byte)'A', (byte)'B',
                                                        (byte)'C', (byte)'D', (byte)'E', (byte)'F' };

        /** @return hex rep of byte (lower case). */
        public static string ToHexStr(byte[] b) => ToHexStr(b, false);

        public static string ToHexStr(byte[] b, bool upperCase) {
            int len = b.Length;
            byte[] digits = new byte[len * 2];
            byte[] hex_rep = upperCase ? HEX_digits : hex_digits;

            for (int i = 0; i < len; i++) {
                digits[i * 2] = hex_rep[(byte)(b[i] >> 4 & 0x0F)];
                digits[i * 2 + 1] = hex_rep[(byte)(b[i] & 0x0F)];
            }
            return Encoding.UTF8.GetString(digits);
        }

        public static int ReadInt(byte[] b, int off) {
            int v0 = ((int)b[off++] & 0xFF);
            v0 |= ((int)b[off++] & 0xFF) << 8;
            v0 |= ((int)b[off++] & 0xFF) << 16;
            v0 |= ((int)b[off]) << 24;
            return v0;
        }

        /** Little endian - byte[] to long */
        public static long ReadLong(byte[] b, int off) {
            long v0 = (long)b[off++] & 0xFF;
            v0 |= ((long)b[off++] & 0xFF) << 8;
            v0 |= ((long)b[off++] & 0xFF) << 16;
            v0 |= ((long)b[off++] & 0xFF) << 24;
            v0 |= ((long)b[off++] & 0xFF) << 32;
            v0 |= ((long)b[off++] & 0xFF) << 40;
            v0 |= ((long)b[off++] & 0xFF) << 48;
            v0 |= ((long)b[off]) << 56;
            return v0;
        }

        /** Little endian - long to byte[] */
        public static void WriteLong(long v, byte[] b, int off) {
            //b[off] = (byte)v; v >>>= 8;
            b[off] = (byte)v;
            v = (int)((uint)v >> 8);
            //b[off + 1] = (byte)v; v >>>= 8;
            b[off + 1] = (byte)v;
            v = (int)((uint)v >> 8);
            //b[off + 2] = (byte)v; v >>>= 8;
            b[off + 2] = (byte)v;
            v = (int)((uint)v >> 8);
            //b[off + 3] = (byte)v; v >>>= 8;
            b[off + 3] = (byte)v;
            v = (int)((uint)v >> 8);
            //b[off + 4] = (byte)v; v >>>= 8;
            b[off + 4] = (byte)v;
            v = (int)((uint)v >> 8);
            //b[off + 5] = (byte)v; v >>>= 8;
            b[off + 5] = (byte)v;
            v = (int)((uint)v >> 8);
            //b[off + 6] = (byte)v; v >>>= 8;
            b[off + 6] = (byte)v;
            v = (int)((uint)v >> 8);
            b[off + 7] = (byte)v;
        }

        /** Little endian - int to byte[] */
        public static void WriteInt(int v, byte[] b, int off) {
            //b[off] = (byte)v; v >>>= 8;
            b[off] = (byte)v;
            v = (int)((uint)v >> 8);
            //b[off + 1] = (byte)v; v >>>= 8;
            b[off + 1] = (byte)v;
            v = (int)((uint)v >> 8);
            //b[off + 2] = (byte)v; v >>>= 8;
            b[off + 2] = (byte)v;
            v = (int)((uint)v >> 8);
            b[off + 3] = (byte)v;
        }
    }
}
