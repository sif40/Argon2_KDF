namespace Argon2_KDF.blake2
{
    public abstract class Spec
    {
        /** pblock size of blake2b */
        public static int param_bytes = 64;

        /** pblock size of blake2b */
        public static int block_bytes = 128;

        /** maximum digest size */
        public static int max_digest_bytes = 64;

        /** maximum key sie */
        public static int max_key_bytes = 64;

        /** maximum salt size */
        public static int max_salt_bytes = 16;

        /** maximum personalization string size */
        public static int max_personalization_bytes = 16;

        /** length of h space vector array */
        public static int state_space_len = 8;

        /** max tree fanout value */
        public static int max_tree_fantout = 0xFF;

        /** max tree depth value */
        public static int max_tree_depth = 0xFF;

        /** max tree leaf length value.Note that this has uint32 semantics
         and thus 0xFFFFFFFF is used as max value limit. */
        public static uint max_tree_leaf_length = 0xFFFFFFFF;

        /** max node offset value. Note that this has uint64 semantics
            and thus 0xFFFFFFFFFFFFFFFFL is used as max value limit. */
        public static ulong max_node_offset = 0xFFFFFFFFFFFFFFFFL;

        /** max tree inner length value */
        public static int max_tree_inner_length = 0xFF;

        /** initialization values map ref-ISpec IV[i] -> slice iv[i*8:i*8+7] */
        public static long[] IV = {
            unchecked((long)0x6a09e667f3bcc908L),
            unchecked((long)0xbb67ae8584caa73bL),
            unchecked((long)0x3c6ef372fe94f82bL),
            unchecked((long)0xa54ff53a5f1d36f1L),
            unchecked((long)0x510e527fade682d1L),
            unchecked((long)0x9b05688c2b3e6c1fL),
            unchecked((long)0x1f83d9abfb41bd6bL),
            unchecked((long)0x5be0cd19137e2179L)
        };

        /** sigma per spec used in compress func generation - for reference only */
        private static readonly sbyte[] l1 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
        private static readonly sbyte[] l2 = { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 };
        private static readonly sbyte[] l3 = { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 };
        private static readonly sbyte[] l4 = { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 };
        private static readonly sbyte[] l5 = { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 };
        private static readonly sbyte[] l6 = { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 };
        private static readonly sbyte[] l7 = { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 };
        private static readonly sbyte[] l8 = { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 };
        private static readonly sbyte[] l9 = { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 };
        private static readonly sbyte[] l10 = { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 };
        private static readonly sbyte[] l11 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
        private static readonly sbyte[] l12 = { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 };
        public static sbyte[][] sigma = {
            l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12
        };
    }
}
