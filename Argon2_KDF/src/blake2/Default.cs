using System;

namespace Argon2_KDF.blake2
{
    public abstract class Default
    {
        public static byte digest_length = Convert.ToByte(Spec.max_digest_bytes);
        public static byte key_length = 0;
        public static byte fanout = 1;
        public static byte depth = 1;
        public static int leaf_length = 0;
        public static long node_offset = 0;
        public static byte node_depth = 0;
        public static byte inner_length = 0;
    }
}
