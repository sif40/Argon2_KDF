using System;

namespace Argon2_KDF.blake2
{
    // ---------------------------------------------------------------------
    // digest parameter (block)
    // ---------------------------------------------------------------------
    /** Blake2b configuration parameters block per spec */
    // REVU: need to review a revert back to non-lazy impl TODO: do & bench
    public class Param /*: AlgorithmParameterSpec*/
    {
        /**
         * default bytes of Blake2b parameter block
         */
        public static byte[] default_bytes = new byte[Spec.param_bytes];
        /**
         * default Blake2b h vector
         */
        public static long[] default_h = new long[Spec.state_space_len];

        /** initialize default_bytes */
        static Param() {
            default_bytes[Xoff.digest_length] = Default.digest_length;
            default_bytes[Xoff.key_length] = Default.key_length;
            default_bytes[Xoff.fanout] = Default.fanout;
            default_bytes[Xoff.depth] = Default.depth;
            /* def. leaf_length is 0 fill and already set by new byte[] */
            /* def. node_offset is 0 fill and already set by new byte[] */
            default_bytes[Xoff.node_depth] = Default.node_depth;
            default_bytes[Xoff.inner_length] = Default.inner_length;
            /* def. salt is 0 fill and already set by new byte[] */
            /* def. personal is 0 fill and already set by new byte[] */

            default_h[0] = LittleEndian.ReadLong(default_bytes, 0);
            default_h[1] = LittleEndian.ReadLong(default_bytes, 8);
            default_h[2] = LittleEndian.ReadLong(default_bytes, 16);
            default_h[3] = LittleEndian.ReadLong(default_bytes, 24);
            default_h[4] = LittleEndian.ReadLong(default_bytes, 32);
            default_h[5] = LittleEndian.ReadLong(default_bytes, 40);
            default_h[6] = LittleEndian.ReadLong(default_bytes, 48);
            default_h[7] = LittleEndian.ReadLong(default_bytes, 56);

            default_h[0] ^= Spec.IV[0];
            default_h[1] ^= Spec.IV[1];
            default_h[2] ^= Spec.IV[2];
            default_h[3] ^= Spec.IV[3];
            default_h[4] ^= Spec.IV[4];
            default_h[5] ^= Spec.IV[5];
            default_h[6] ^= Spec.IV[6];
            default_h[7] ^= Spec.IV[7];
        }

        //    static {
        //        default_bytes[Xoff.digest_length] = Default.digest_length;
        //        default_bytes[Xoff.key_length] = Default.key_length;
        //        default_bytes[Xoff.fanout] = Default.fanout;
        //        default_bytes[Xoff.depth] = Default.depth;
        //        /* def. leaf_length is 0 fill and already set by new byte[] */
        //        /* def. node_offset is 0 fill and already set by new byte[] */
        //        default_bytes[Xoff.node_depth] = Default.node_depth;
        //        default_bytes[Xoff.inner_length] = Default.inner_length;
        //        /* def. salt is 0 fill and already set by new byte[] */
        //        /* def. personal is 0 fill and already set by new byte[] */
        //    }

        //static {
        //        default_h[0] = readLong(default_bytes, 0  );
        //default_h[1] = ReadLong(default_bytes, 8  );
        //default_h[2] = ReadLong(default_bytes, 16 );
        //default_h[3] = ReadLong(default_bytes, 24 );
        //default_h[4] = ReadLong(default_bytes, 32 );
        //default_h[5] = ReadLong(default_bytes, 40 );
        //default_h[6] = ReadLong(default_bytes, 48 );
        //default_h[7] = ReadLong(default_bytes, 56 );

        //default_h[0] ^= Spec.IV[0];
        //        default_h[1] ^= Spec.IV[1];
        //        default_h[2] ^= Spec.IV[2];
        //        default_h[3] ^= Spec.IV[3];
        //        default_h[4] ^= Spec.IV[4];
        //        default_h[5] ^= Spec.IV[5];
        //        default_h[6] ^= Spec.IV[6];
        //        default_h[7] ^= Spec.IV[7];
        //    }

        /** */
        private long[] h = new long[Spec.state_space_len];
        /** */
        private bool hasKey = false;
        /** not sure how to make this secure - TODO */
        public byte[] key_bytes = null;
        /** */
        private byte[] bytes = null;
        /** */
        public Param() {
            Array.Copy(default_h, 0, h, 0, Spec.state_space_len);
        }

        /** */
        public long[] Initialized_H() {
            return h;
        }

        /** package only - copy returned - do not use in functional loops */
        public byte[] GetBytes() {
            LazyInitBytes();
            byte[] copy = new byte[bytes.Length];
            Array.Copy(bytes, 0, copy, 0, bytes.Length);
            return copy;
        }

        public byte GetByteParam(int xoffset) {
            byte[] _bytes = bytes;
            if (_bytes == null) _bytes = Param.default_bytes;
            return _bytes[xoffset];
        }

        public int GetIntParam(int xoffset) {
            byte[] _bytes = bytes;
            if (_bytes == null) _bytes = Param.default_bytes;
            return LittleEndian.ReadInt(_bytes, xoffset);
        }

        public long GetLongParam(int xoffset) {
            byte[] _bytes = bytes;
            if (_bytes == null) _bytes = Param.default_bytes;
            return LittleEndian.ReadLong(_bytes, xoffset);
        }

        // TODO same for tree params depth, fanout, inner, node-depth, node-offset
        public int GetDigestLength() {
            return (int)GetByteParam(Xoff.digest_length);
        }

        /* 0-7 inclusive */
        public Param SetDigestLength(int len) {
            LazyInitBytes();
            bytes[Xoff.digest_length] = (byte)len;
            h[0] = LittleEndian.ReadLong(bytes, 0);
            h[0] ^= Spec.IV[0];
            return this;
        }

        public int GetKeyLength() {
            return (int)GetByteParam(Xoff.key_length);
        }

        public int GetFanout() {
            return (int)GetByteParam(Xoff.fanout);
        }

        public Param SetFanout(int fanout) {

            LazyInitBytes();
            bytes[Xoff.fanout] = (byte)fanout;
            h[0] = LittleEndian.ReadLong(bytes, 0);
            h[0] ^= Spec.IV[0];
            return this;
        }

        public int GetDepth() {
            return (int)GetByteParam(Xoff.depth);
        }

        public Param SetDepth(int depth) {
            LazyInitBytes();
            bytes[Xoff.depth] = (byte)depth;
            h[0] = LittleEndian.ReadLong(bytes, 0);
            h[0] ^= Spec.IV[0];
            return this;
        }

        public int GetLeafLength() => GetIntParam(Xoff.leaf_length);

        public Param SetLeafLength(int leaf_length) {
            LazyInitBytes();
            LittleEndian.WriteInt(leaf_length, bytes, Xoff.leaf_length);
            h[0] = LittleEndian.ReadLong(bytes, 0);
            h[0] ^= Spec.IV[0];
            return this;
        }

        public long GetNodeOffset() => GetLongParam(Xoff.node_offset);

        /* 8-15 inclusive */
        public Param SetNodeOffset(long node_offset) {
            LazyInitBytes();
            LittleEndian.WriteLong(node_offset, bytes, Xoff.node_offset);
            h[1] = LittleEndian.ReadLong(bytes, Xoff.node_offset);
            h[1] ^= Spec.IV[1];
            return this;
        }

        public int GetNodeDepth() => (int)GetByteParam(Xoff.node_depth);

        /* 16-23 inclusive */
        public Param SetNodeDepth(int node_depth) {
            LazyInitBytes();
            bytes[Xoff.node_depth] = (byte)node_depth;
            h[2] = LittleEndian.ReadLong(bytes, Xoff.node_depth);
            h[2] ^= Spec.IV[2];
            h[3] = LittleEndian.ReadLong(bytes, Xoff.node_depth + 8);
            h[3] ^= Spec.IV[3];
            return this;
        }

        public int GetInnerLength() => (int)GetByteParam(Xoff.inner_length);

        public Param SetInnerLength(int inner_length) {
            LazyInitBytes();
            bytes[Xoff.inner_length] = (byte)inner_length;
            h[2] = LittleEndian.ReadLong(bytes, Xoff.node_depth);
            h[2] ^= Spec.IV[2];
            h[3] = LittleEndian.ReadLong(bytes, Xoff.node_depth + 8);
            h[3] ^= Spec.IV[3];
            return this;
        }

        public bool HasKey() => hasKey;

        public /*override*/ Param Clone() {
            Param clone = new Param();
            Array.Copy(this.h, 0, clone.h, 0, h.Length);
            clone.LazyInitBytes();
            Array.Copy(this.bytes, 0, clone.bytes, 0, this.bytes.Length);

            if (HasKey()) {
                clone.hasKey = this.hasKey;
                clone.key_bytes = new byte[Spec.max_key_bytes * 2];
                Array.Copy(this.key_bytes, 0, clone.key_bytes, 0, this.key_bytes.Length);
            }
            return clone;
        }

        ////////////////////////////////////////////////////////////////////////
        /// lazy setters - write directly to the bytes image of param block ////
        ////////////////////////////////////////////////////////////////////////
        public void LazyInitBytes() {
            if (bytes == null) {
                bytes = new byte[Spec.param_bytes];
                Array.Copy(Param.default_bytes, 0, bytes, 0, Spec.param_bytes);
            }
        }

        //public Param SetKey(Key key) {
        //    byte[] keybytes = key.GetEncoded();
        //    return this.SetKey(keybytes);
        //}

        public Param SetKey(byte[] key) {
            // zeropad keybytes
            this.key_bytes = new byte[Spec.max_key_bytes * 2];
            Array.Copy(key, 0, this.key_bytes, 0, key.Length);
            LazyInitBytes();
            bytes[Xoff.key_length] = (byte)key.Length; // checked c ref; this is correct
            h[0] = LittleEndian.ReadLong(bytes, 0);
            h[0] ^= Spec.IV[0];
            this.hasKey = true;
            return this;
        }

        /* 32-47 inclusive */
        public Param SetSalt(byte[] salt) {
            LazyInitBytes();
            //Arrays.fill(bytes, Xoff.salt, Xoff.salt + Spec.max_salt_bytes, (byte)0);
            Util.Fill(bytes, Xoff.salt, Xoff.salt + Spec.max_salt_bytes, (byte)0);
            Array.Copy(salt, 0, bytes, Xoff.salt, salt.Length);
            h[4] = LittleEndian.ReadLong(bytes, Xoff.salt);
            h[4] ^= Spec.IV[4];
            h[5] = LittleEndian.ReadLong(bytes, Xoff.salt + 8);
            h[5] ^= Spec.IV[5];
            return this;
        }

        /* 48-63 inclusive */
        public Param SetPersonal(byte[] personal) {
            LazyInitBytes();
            Util.Fill(bytes, Xoff.personal, Xoff.personal + Spec.max_personalization_bytes, (byte)0);
            Array.Copy(personal, 0, bytes, Xoff.personal, personal.Length);
            h[6] = LittleEndian.ReadLong(bytes, Xoff.personal);
            h[6] ^= Spec.IV[6];
            h[7] = LittleEndian.ReadLong(bytes, Xoff.personal + 8);
            h[7] ^= Spec.IV[7];
            return this;
        }
    }
}
