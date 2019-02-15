using System;
using System.Collections.Generic;
using System.Text;

namespace Argon2_KDF.blake2
{
    /* 24-31 masked by reserved and remain unchanged */

    public abstract class Xoff
    {
        public static int digest_length = 0;
        public static int key_length = 1;
        public static int fanout = 2;
        public static int depth = 3;
        public static int leaf_length = 4;
        public static int node_offset = 8;
        public static int node_depth = 16;
        public static int inner_length = 17;
        public static int reserved = 18;
        public static int salt = 32;
        public static int personal = 48;
    }
}
