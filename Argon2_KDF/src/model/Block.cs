using System;
using System.Text;

namespace Argon2_KDF.model
{
    public class Block
    {
        /* 128 * 8 Byte QWords */
        public long[] v;

        public Block() {
            v = new long[Constants.ARGON2_QWORDS_IN_BLOCK];
        }

        public void FromBytes(byte[] input) {
            for (int i = 0; i < v.Length; i++) {
                byte[] slice = CopyOfRange(input, i * 8, (i + 1) * 8);
                v[i] = Util.LittleEndianBytesToLong(slice);
            }
        }

        public byte[] ToBytes() {
            byte[] result = new byte[Constants.ARGON2_BLOCK_SIZE];

            for (int i = 0; i < v.Length; i++) {
                byte[] bytes = Util.LongToLittleEndianBytes(v[i]);
                Array.Copy(bytes, 0, result, i * bytes.Length, bytes.Length);
            }

            return result;
        }

        private byte[] CopyOfRange(byte[] src, int start, int end) {
            int len = end - start;
            byte[] dest = new byte[len];
            Array.Copy(src, start, dest, 0, len);
            return dest;
        }

        public void CopyBlock(Block other) => Array.Copy(other.v, 0, v, 0, v.Length);

        public void Xor(Block b1, Block b2) {
            for (int i = 0; i < v.Length; i++) {
                v[i] = b1.v[i] ^ b2.v[i];
            }
        }

        public void Xor(Block b1, Block b2, Block b3) {
            for (int i = 0; i < v.Length; i++) {
                v[i] = b1.v[i] ^ b2.v[i] ^ b3.v[i];
            }
        }

        public void XorWith(Block other) {
            for (int i = 0; i < v.Length; i++) {
                v[i] = v[i] ^ other.v[i];
            }
        }

        public override string ToString() {
            StringBuilder result = new StringBuilder();
            foreach (long value in v) {
                result.Append(Util.BytesToHexString(Util.LongToLittleEndianBytes(value)));
            }

            return result.ToString();
        }

        public void Clear() => Array.Fill(v, 0);
    }
}
