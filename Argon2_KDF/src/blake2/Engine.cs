using System;

namespace Argon2_KDF.blake2
{
    // ---------------------------------------------------------------------
    // Engine
    // ---------------------------------------------------------------------
    public class Engine : IBlake2b
    {
        /* G0 sigmas */
        private static int[] _sig_g00 = { 0, 14, 11, 7, 9, 2, 12, 13, 6, 10, 0, 14, };
        private static int[] _sig_g01 = { 1, 10, 8, 9, 0, 12, 5, 11, 15, 2, 1, 10, };

        /* G1 sigmas */
        private static int[] _sig_g10 = { 2, 4, 12, 3, 5, 6, 1, 7, 14, 8, 2, 4, };
        private static int[] _sig_g11 = { 3, 8, 0, 1, 7, 10, 15, 14, 9, 4, 3, 8, };

        /* G2 sigmas */
        private static int[] _sig_g20 = { 4, 9, 5, 13, 2, 0, 14, 12, 11, 7, 4, 9, };
        private static int[] _sig_g21 = { 5, 15, 2, 12, 4, 11, 13, 1, 3, 6, 5, 15, };

        /* G3 sigmas */
        private static int[] _sig_g30 = { 6, 13, 15, 11, 10, 8, 4, 3, 0, 1, 6, 13, };
        private static int[] _sig_g31 = { 7, 6, 13, 14, 15, 3, 10, 9, 8, 5, 7, 6, };

        /* G4 sigmas */
        private static int[] _sig_g40 = { 8, 1, 10, 2, 14, 4, 0, 5, 12, 15, 8, 1, };
        private static int[] _sig_g41 = { 9, 12, 14, 6, 1, 13, 7, 0, 2, 11, 9, 12, };

        /* G5 sigmas */
        private static int[] _sig_g50 = { 10, 0, 3, 5, 11, 7, 6, 15, 13, 9, 10, 0, };
        private static int[] _sig_g51 = { 11, 2, 6, 10, 12, 5, 3, 4, 7, 14, 11, 2, };

        /* G6 sigmas */
        private static int[] _sig_g60 = { 12, 11, 7, 4, 6, 15, 9, 8, 1, 3, 12, 11, };
        private static int[] _sig_g61 = { 13, 7, 1, 0, 8, 14, 2, 6, 4, 12, 13, 7, };

        /* G7 sigmas */
        private static int[] _sig_g70 = { 14, 5, 9, 15, 3, 1, 8, 2, 10, 13, 14, 5, };
        private static int[] _sig_g71 = { 15, 3, 4, 8, 13, 9, 11, 10, 5, 0, 15, 3, };

        // ---------------------------------------------------------------------
        // Blake2b State(+) per reference implementation
        // ---------------------------------------------------------------------
        // REVU: address _lastNode TODO part of the Tree/incremental
        /**
         * read only
         */
        private static byte[] _zeropad = new byte[Spec.block_bytes];
        /**
         * per spec
         */
        private long[] _h = new long[8];
        /** per spec */
        private long[] _t = new long[2];
        /** per spec */
        private long[] _f = new long[2];
        /** pulled up 2b optimal */
        private long[] _m = new long[16];
        /** pulled up 2b optimal */
        private long[] _v = new long[16];

        /** compressor cache _buffer */
        private byte[] _buffer;
        /** configuration params */
        private Param _param;
        /** digest length from init _param - copied here on init */
        private int _outlen;
        /**
         * per spec (tree)
         */
        private bool _lastNode = false;
        /**
         * compressor cache _buffer offset/cached data length
         */
        private int _buflen;
        /** to support update(byte) */
        private byte[] _oneByte;

        /** Basic use constructor pending (TODO) JCA/JCE compliance */
        public Engine() : this(new Param()) {
            //this(new Param());
        }

        // ---------------------------------------------------------------------
        // Ctor & Initialization
        // ---------------------------------------------------------------------

        /** User provided Param for custom configurations */
        public Engine(Param param) {
            _param = param;
            _buffer = new byte[Spec.block_bytes];
            _oneByte = new byte[1];
            _outlen = param.GetDigestLength();

            if (param.GetDepth() > /*Param.*/Default.depth) {
                int ndepth = param.GetNodeDepth();
                long nxoff = param.GetNodeOffset();
                if (ndepth == param.GetDepth() - 1) {
                    _lastNode = true;
                }
                else if (param.GetNodeOffset() == param.GetFanout() - 1) {
                    _lastNode = true;
                }
            }

            Initialize();

            //			Debug.dumpBuffer(System.out, "_param bytes at init", _param.getBytes());

        }

        //public static void Main(string[] args) {
        //    IBlake2b mac = Blake2b.Mac.NewInstance("LOVE".getBytes());
        //    final sbyte[] hash = mac.Digest("Salaam!".getBytes());
        //    //			Debug.dumpBuffer(System.out, "-- mac hash --", hash);
        //}

        private void Initialize() {
            // state vector _h - copy values to address reset() requests
            Array.Copy(_param.Initialized_H(), 0, _h, 0, Spec.state_space_len);

            //			Debug.dumpArray("init H", this._h);
            // if we have a key update initial block
            // Note _param has zero padded key_bytes to Spec.max_key_bytes
            if (_param.HasKey()) {
                Update(_param.key_bytes, 0, Spec.block_bytes);
            }
        }

        /**
         * {@inheritDoc}
         */
        public /*override*/ void Reset() {
            // reset cache
            _buflen = 0;
            for (int i = 0; i < _buffer.Length; i++) {
                _buffer[i] = (byte)0;
            }

            // reset flags
            _f[0] = 0L;
            _f[1] = 0L;

            // reset counters
            _t[0] = 0L;
            _t[1] = 0L;

            // reset state vector
            // NOTE: keep as last stmt as init calls update0 for MACs.
            Initialize();
        }

        // ---------------------------------------------------------------------
        // interface: Blake2b API
        // ---------------------------------------------------------------------

        /** {@inheritDoc} */
        public /*override*/ void Update(byte[] b, int off, int len) {
            if (b == null) {
                throw new ArgumentException("input _buffer (b) is null");
            }
            /* zero or more calls to compress */
            // REVU: possibly the double buffering of c-ref is more sensible ..
            //       regardless, the hotspot is in the compress, as expected.
            while (len > 0) {
                if (_buflen == 0) {
                    /* try compressing direct from input ? */
                    while (len > Spec.block_bytes) {
                        _t[0] += Spec.block_bytes;
                        _t[1] += _t[0] == 0 ? 1 : 0;
                        Compress(b, off);
                        len -= Spec.block_bytes;
                        off += Spec.block_bytes;
                    }
                }
                else if (_buflen == Spec.block_bytes) {
                    /* flush */
                    _t[0] += Spec.block_bytes;
                    _t[1] += _t[0] == 0 ? 1 : 0;
                    Compress(_buffer, 0);
                    _buflen = 0;
                    continue;
                }

                // "are we there yet?"
                if (len == 0) return;

                int cap = Spec.block_bytes - _buflen;
                int fill = len > cap ? cap : len;
                Array.Copy(b, off, _buffer, _buflen, fill);
                _buflen += fill;
                len -= fill;
                off += fill;
            }
        }

        /** {@inheritDoc} */
        public /*override*/ void Update(byte b) {
            _oneByte[0] = b;
            Update(_oneByte, 0, 1);
        }

        /** {@inheritDoc} */
        public /*override*/ void Update(byte[] input) => Update(input, 0, input.Length);

        /** {@inheritDoc} */
        public /*override*/ void Digest(byte[] output, int off, int len) {
            // zero pad last block; set last block flags; and compress
            Array.Copy(_zeropad, 0, _buffer, _buflen, Spec.block_bytes - _buflen);
            if (_buflen > 0) {
                _t[0] += _buflen;
                _t[1] += _t[0] == 0 ? 1 : 0;
            }

            _f[Flag.last_block] = unchecked((long)0xFFFFFFFFFFFFFFFFL);
            _f[Flag.last_node] = _lastNode ? unchecked((long)0xFFFFFFFFFFFFFFFFL) : unchecked((long)0x0L);

            // compres and write final out (truncated to len) to output
            Compress(_buffer, 0);
            Hashout(output, off, len);

            Reset();
        }

        /// <summary>
        /// throws IllegalArgumentException
        /// </summary>
        public /*override*/ byte[] Digest() {
            byte[] _out = new byte[_outlen];
            Digest(_out, 0, _outlen);
            return _out;
        }

        /** {@inheritDoc} */
        public /*override*/ byte[] Digest(byte[] input) {
            Update(input, 0, input.Length);
            return Digest();
        }

        /**
         * write out the digest output from the '_h' registers.
         * truncate full output if necessary.
         */
        private void Hashout(byte[] _out, int offset, int hashlen) {
            // write max number of whole longs
            int lcnt = (int)((uint)hashlen >> 3);
            long v = 0;
            int i = offset;
            for (int w = 0; w < lcnt; w++) {
                v = _h[w];
                //_out [i++ ] = (byte) _v; _v >>>= 8;
                _out[i++] = (byte)v;
                v = (long)((ulong)v >> 8);
                //_out [i++ ] = (byte) _v; _v >>>= 8;
                _out[i++] = (byte)v;
                v = (long)((ulong)v >> 8);
                //_out [i++ ] = (byte) _v; _v >>>= 8;
                _out[i++] = (byte)v;
                v = (long)((ulong)v >> 8);
                //_out [i++ ] = (byte) _v; _v >>>= 8;
                _out[i++] = (byte)v;
                v = (long)((ulong)v >> 8);
                //_out [i++ ] = (byte) _v; _v >>>= 8;
                _out[i++] = (byte)v;
                v = (long)((ulong)v >> 8);
                //_out [i++ ] = (byte) _v; _v >>>= 8;
                _out[i++] = (byte)v;
                v = (long)((ulong)v >> 8);
                //_out [i++ ] = (byte) _v; _v >>>= 8;
                _out[i++] = (byte)v;
                v = (long)((ulong)v >> 8);
                _out[i++] = (byte)v;
            }

            // basta?
            if (hashlen == Spec.max_digest_bytes) return;

            // write the remaining bytes of a partial long value
            v = _h[lcnt];
            i = lcnt << 3;
            while (i < hashlen) {
                _out[offset + i] = (byte)v;
                v = (long)((ulong)v >> 8);
                ++i;
            }
        }

        // ---------------------------------------------------------------------
        // Internal Ops
        // ---------------------------------------------------------------------

        /** compress Spec.block_bytes data from b, from offset */
        private void Compress(byte[] b, int offset) {

            // set _m registers
            // REVU: some small gains still possible here.
            _m[0] = (long)b[offset] & 0xFF;
            _m[0] |= ((long)b[offset + 1] & 0xFF) << 8;
            _m[0] |= ((long)b[offset + 2] & 0xFF) << 16;
            _m[0] |= ((long)b[offset + 3] & 0xFF) << 24;
            _m[0] |= ((long)b[offset + 4] & 0xFF) << 32;
            _m[0] |= ((long)b[offset + 5] & 0xFF) << 40;
            _m[0] |= ((long)b[offset + 6] & 0xFF) << 48;
            _m[0] |= ((long)b[offset + 7]) << 56;

            _m[1] = (long)b[offset + 8] & 0xFF;
            _m[1] |= ((long)b[offset + 9] & 0xFF) << 8;
            _m[1] |= ((long)b[offset + 10] & 0xFF) << 16;
            _m[1] |= ((long)b[offset + 11] & 0xFF) << 24;
            _m[1] |= ((long)b[offset + 12] & 0xFF) << 32;
            _m[1] |= ((long)b[offset + 13] & 0xFF) << 40;
            _m[1] |= ((long)b[offset + 14] & 0xFF) << 48;
            _m[1] |= ((long)b[offset + 15]) << 56;

            _m[2] = (long)b[offset + 16] & 0xFF;
            _m[2] |= ((long)b[offset + 17] & 0xFF) << 8;
            _m[2] |= ((long)b[offset + 18] & 0xFF) << 16;
            _m[2] |= ((long)b[offset + 19] & 0xFF) << 24;
            _m[2] |= ((long)b[offset + 20] & 0xFF) << 32;
            _m[2] |= ((long)b[offset + 21] & 0xFF) << 40;
            _m[2] |= ((long)b[offset + 22] & 0xFF) << 48;
            _m[2] |= ((long)b[offset + 23]) << 56;

            _m[3] = (long)b[offset + 24] & 0xFF;
            _m[3] |= ((long)b[offset + 25] & 0xFF) << 8;
            _m[3] |= ((long)b[offset + 26] & 0xFF) << 16;
            _m[3] |= ((long)b[offset + 27] & 0xFF) << 24;
            _m[3] |= ((long)b[offset + 28] & 0xFF) << 32;
            _m[3] |= ((long)b[offset + 29] & 0xFF) << 40;
            _m[3] |= ((long)b[offset + 30] & 0xFF) << 48;
            _m[3] |= ((long)b[offset + 31]) << 56;

            _m[4] = (long)b[offset + 32] & 0xFF;
            _m[4] |= ((long)b[offset + 33] & 0xFF) << 8;
            _m[4] |= ((long)b[offset + 34] & 0xFF) << 16;
            _m[4] |= ((long)b[offset + 35] & 0xFF) << 24;
            _m[4] |= ((long)b[offset + 36] & 0xFF) << 32;
            _m[4] |= ((long)b[offset + 37] & 0xFF) << 40;
            _m[4] |= ((long)b[offset + 38] & 0xFF) << 48;
            _m[4] |= ((long)b[offset + 39]) << 56;

            _m[5] = (long)b[offset + 40] & 0xFF;
            _m[5] |= ((long)b[offset + 41] & 0xFF) << 8;
            _m[5] |= ((long)b[offset + 42] & 0xFF) << 16;
            _m[5] |= ((long)b[offset + 43] & 0xFF) << 24;
            _m[5] |= ((long)b[offset + 44] & 0xFF) << 32;
            _m[5] |= ((long)b[offset + 45] & 0xFF) << 40;
            _m[5] |= ((long)b[offset + 46] & 0xFF) << 48;
            _m[5] |= ((long)b[offset + 47]) << 56;

            _m[6] = (long)b[offset + 48] & 0xFF;
            _m[6] |= ((long)b[offset + 49] & 0xFF) << 8;
            _m[6] |= ((long)b[offset + 50] & 0xFF) << 16;
            _m[6] |= ((long)b[offset + 51] & 0xFF) << 24;
            _m[6] |= ((long)b[offset + 52] & 0xFF) << 32;
            _m[6] |= ((long)b[offset + 53] & 0xFF) << 40;
            _m[6] |= ((long)b[offset + 54] & 0xFF) << 48;
            _m[6] |= ((long)b[offset + 55]) << 56;

            _m[7] = (long)b[offset + 56] & 0xFF;
            _m[7] |= ((long)b[offset + 57] & 0xFF) << 8;
            _m[7] |= ((long)b[offset + 58] & 0xFF) << 16;
            _m[7] |= ((long)b[offset + 59] & 0xFF) << 24;
            _m[7] |= ((long)b[offset + 60] & 0xFF) << 32;
            _m[7] |= ((long)b[offset + 61] & 0xFF) << 40;
            _m[7] |= ((long)b[offset + 62] & 0xFF) << 48;
            _m[7] |= ((long)b[offset + 63]) << 56;

            _m[8] = (long)b[offset + 64] & 0xFF;
            _m[8] |= ((long)b[offset + 65] & 0xFF) << 8;
            _m[8] |= ((long)b[offset + 66] & 0xFF) << 16;
            _m[8] |= ((long)b[offset + 67] & 0xFF) << 24;
            _m[8] |= ((long)b[offset + 68] & 0xFF) << 32;
            _m[8] |= ((long)b[offset + 69] & 0xFF) << 40;
            _m[8] |= ((long)b[offset + 70] & 0xFF) << 48;
            _m[8] |= ((long)b[offset + 71]) << 56;

            _m[9] = (long)b[offset + 72] & 0xFF;
            _m[9] |= ((long)b[offset + 73] & 0xFF) << 8;
            _m[9] |= ((long)b[offset + 74] & 0xFF) << 16;
            _m[9] |= ((long)b[offset + 75] & 0xFF) << 24;
            _m[9] |= ((long)b[offset + 76] & 0xFF) << 32;
            _m[9] |= ((long)b[offset + 77] & 0xFF) << 40;
            _m[9] |= ((long)b[offset + 78] & 0xFF) << 48;
            _m[9] |= ((long)b[offset + 79]) << 56;

            _m[10] = (long)b[offset + 80] & 0xFF;
            _m[10] |= ((long)b[offset + 81] & 0xFF) << 8;
            _m[10] |= ((long)b[offset + 82] & 0xFF) << 16;
            _m[10] |= ((long)b[offset + 83] & 0xFF) << 24;
            _m[10] |= ((long)b[offset + 84] & 0xFF) << 32;
            _m[10] |= ((long)b[offset + 85] & 0xFF) << 40;
            _m[10] |= ((long)b[offset + 86] & 0xFF) << 48;
            _m[10] |= ((long)b[offset + 87]) << 56;

            _m[11] = (long)b[offset + 88] & 0xFF;
            _m[11] |= ((long)b[offset + 89] & 0xFF) << 8;
            _m[11] |= ((long)b[offset + 90] & 0xFF) << 16;
            _m[11] |= ((long)b[offset + 91] & 0xFF) << 24;
            _m[11] |= ((long)b[offset + 92] & 0xFF) << 32;
            _m[11] |= ((long)b[offset + 93] & 0xFF) << 40;
            _m[11] |= ((long)b[offset + 94] & 0xFF) << 48;
            _m[11] |= ((long)b[offset + 95]) << 56;

            _m[12] = (long)b[offset + 96] & 0xFF;
            _m[12] |= ((long)b[offset + 97] & 0xFF) << 8;
            _m[12] |= ((long)b[offset + 98] & 0xFF) << 16;
            _m[12] |= ((long)b[offset + 99] & 0xFF) << 24;
            _m[12] |= ((long)b[offset + 100] & 0xFF) << 32;
            _m[12] |= ((long)b[offset + 101] & 0xFF) << 40;
            _m[12] |= ((long)b[offset + 102] & 0xFF) << 48;
            _m[12] |= ((long)b[offset + 103]) << 56;

            _m[13] = (long)b[offset + 104] & 0xFF;
            _m[13] |= ((long)b[offset + 105] & 0xFF) << 8;
            _m[13] |= ((long)b[offset + 106] & 0xFF) << 16;
            _m[13] |= ((long)b[offset + 107] & 0xFF) << 24;
            _m[13] |= ((long)b[offset + 108] & 0xFF) << 32;
            _m[13] |= ((long)b[offset + 109] & 0xFF) << 40;
            _m[13] |= ((long)b[offset + 110] & 0xFF) << 48;
            _m[13] |= ((long)b[offset + 111]) << 56;

            _m[14] = (long)b[offset + 112] & 0xFF;
            _m[14] |= ((long)b[offset + 113] & 0xFF) << 8;
            _m[14] |= ((long)b[offset + 114] & 0xFF) << 16;
            _m[14] |= ((long)b[offset + 115] & 0xFF) << 24;
            _m[14] |= ((long)b[offset + 116] & 0xFF) << 32;
            _m[14] |= ((long)b[offset + 117] & 0xFF) << 40;
            _m[14] |= ((long)b[offset + 118] & 0xFF) << 48;
            _m[14] |= ((long)b[offset + 119]) << 56;

            _m[15] = (long)b[offset + 120] & 0xFF;
            _m[15] |= ((long)b[offset + 121] & 0xFF) << 8;
            _m[15] |= ((long)b[offset + 122] & 0xFF) << 16;
            _m[15] |= ((long)b[offset + 123] & 0xFF) << 24;
            _m[15] |= ((long)b[offset + 124] & 0xFF) << 32;
            _m[15] |= ((long)b[offset + 125] & 0xFF) << 40;
            _m[15] |= ((long)b[offset + 126] & 0xFF) << 48;
            _m[15] |= ((long)b[offset + 127]) << 56;
            //			Debug.dumpArray("_m @ compress", _m);
            //
            //			Debug.dumpArray("_h @ compress", _h);
            //			Debug.dumpArray("_t @ compress", _t);
            //			Debug.dumpArray("_f @ compress", _f);

            // set _v registers
            _v[0] = _h[0];
            _v[1] = _h[1];
            _v[2] = _h[2];
            _v[3] = _h[3];
            _v[4] = _h[4];
            _v[5] = _h[5];
            _v[6] = _h[6];
            _v[7] = _h[7];
            _v[8] = unchecked((long)0x6a09e667f3bcc908L);
            _v[9] = unchecked((long)0xbb67ae8584caa73bL);
            _v[10] = unchecked((long)0x3c6ef372fe94f82bL);
            _v[11] = unchecked((long)0xa54ff53a5f1d36f1L);
            _v[12] = _t[0] ^ unchecked((long)0x510e527fade682d1L);
            _v[13] = _t[1] ^ unchecked((long)0x9b05688c2b3e6c1fL);
            _v[14] = _f[0] ^ unchecked((long)0x1f83d9abfb41bd6bL);
            _v[15] = _f[1] ^ unchecked((long)0x5be0cd19137e2179L);

            //			Debug.dumpArray("_v @ compress", _v);
            // the rounds
            // REVU: let's try unrolling this again TODO do & bench
            for (int r = 0; r < 12; r++) {
                /**        G (r, 0, 0, 4,  8, 12); */
                _v[0] = _v[0] + _v[4] + _m[_sig_g00[r]];
                _v[12] ^= _v[0];
                //_v[12] = (_v[12] << 32) | (_v[12] >>> 32);
                _v[12] = (_v[12] << 32) | (long)((ulong)_v[12] >> 32);
                _v[8] = _v[8] + _v[12];
                _v[4] ^= _v[8];
                //_v[4] = (_v[4] >>> 24) | (_v[4] << 40);
                _v[4] = (long)((ulong)_v[4] >> 24) | (_v[4] << 40);
                _v[0] = _v[0] + _v[4] + _m[_sig_g01[r]];
                _v[12] ^= _v[0];
                //_v[12] = (_v[12] >>> 16) | (_v[12] << 48);
                _v[12] = (long)((ulong)_v[12] >> 16) | (_v[12] << 48);
                _v[8] = _v[8] + _v[12];
                _v[4] ^= _v[8];
                //_v[4] = (_v[4] << 1) | (_v[4] >>> 63);
                _v[4] = (_v[4] << 1) | (long)((ulong)_v[4] >> 63);

                /**        G (r, 1, 1, 5,  9, 13); */

                _v[1] = _v[1] + _v[5] + _m[_sig_g10[r]];
                _v[13] ^= _v[1];
                //_v[13] = (_v[13] << 32) | (_v[13] >>> 32);
                _v[13] = (_v[13] << 32) | (long)((ulong)_v[13] >> 32);
                _v[9] = _v[9] + _v[13];
                _v[5] ^= _v[9];
                //_v[5] = (_v[5] >>> 24) | (_v[5] << 40);
                _v[5] = (long)((ulong)_v[5] >> 24) | (_v[5] << 40);
                _v[1] = _v[1] + _v[5] + _m[_sig_g11[r]];
                _v[13] ^= _v[1];
                //_v[13] = (_v[13] >>> 16) | (_v[13] << 48);
                _v[13] = (long)((ulong)_v[13] >> 16) | (_v[13] << 48);
                _v[9] = _v[9] + _v[13];
                _v[5] ^= _v[9];
                //_v[5] = (_v[5] << 1) | (_v[5] >>> 63);
                _v[5] = (_v[5] << 1) | (long)((ulong)_v[5] >> 63);

                /**        G (r, 2, 2, 6, 10, 14); */

                _v[2] = _v[2] + _v[6] + _m[_sig_g20[r]];
                _v[14] ^= _v[2];
                //_v[14] = (_v[14] << 32) | (_v[14] >>> 32);
                _v[14] = (_v[14] << 32) | (long)((ulong)_v[14] >> 32);
                _v[10] = _v[10] + _v[14];
                _v[6] ^= _v[10];
                //_v[6] = (_v[6] >>> 24) | (_v[6] << 40);
                _v[6] = (long)((ulong)_v[6] >> 24) | (_v[6] << 40);
                _v[2] = _v[2] + _v[6] + _m[_sig_g21[r]];
                _v[14] ^= _v[2];
                //_v[14] = (_v[14] >>> 16) | (_v[14] << 48);
                _v[14] = (long)((ulong)_v[14] >> 16) | (_v[14] << 48);
                _v[10] = _v[10] + _v[14];
                _v[6] ^= _v[10];
                //_v[6] = (_v[6] << 1) | (_v[6] >>> 63);
                _v[6] = (_v[6] << 1) | (long)((ulong)_v[6] >> 63);

                /**        G (r, 3, 3, 7, 11, 15); */

                _v[3] = _v[3] + _v[7] + _m[_sig_g30[r]];
                _v[15] ^= _v[3];
                //_v[15] = (_v[15] << 32) | (_v[15] >>> 32);
                _v[15] = (_v[15] << 32) | (long)((ulong)_v[15] >> 32);
                _v[11] = _v[11] + _v[15];
                _v[7] ^= _v[11];
                //_v[7] = (_v[7] >>> 24) | (_v[7] << 40);
                _v[7] = (long)((ulong)_v[7] >> 24) | (_v[7] << 40);
                _v[3] = _v[3] + _v[7] + _m[_sig_g31[r]];
                _v[15] ^= _v[3];
                //_v[15] = (_v[15] >>> 16) | (_v[15] << 48);
                _v[15] = (long)((ulong)_v[15] >> 16) | (_v[15] << 48);
                _v[11] = _v[11] + _v[15];
                _v[7] ^= _v[11];
                //_v[7] = (_v[7] << 1) | (_v[7] >>> 63);
                _v[7] = (_v[7] << 1) | (long)((ulong)_v[7] >> 63);

                /**        G (r, 4, 0, 5, 10, 15); */

                _v[0] = _v[0] + _v[5] + _m[_sig_g40[r]];
                _v[15] ^= _v[0];
                //_v[15] = (_v[15] << 32) | (_v[15] >>> 32);
                _v[15] = (_v[15] << 32) | (long)((ulong)_v[15] >> 32);
                _v[10] = _v[10] + _v[15];
                _v[5] ^= _v[10];
                //_v[5] = (_v[5] >>> 24) | (_v[5] << 40);
                _v[5] = (long)((ulong)_v[5] >> 24) | (_v[5] << 40);
                _v[0] = _v[0] + _v[5] + _m[_sig_g41[r]];
                _v[15] ^= _v[0];
                //_v[15] = (_v[15] >>> 16) | (_v[15] << 48);
                _v[15] = (long)((ulong)_v[15] >> 16) | (_v[15] << 48);
                _v[10] = _v[10] + _v[15];
                _v[5] ^= _v[10];
                //_v[5] = (_v[5] << 1) | (_v[5] >>> 63);
                _v[5] = (_v[5] << 1) | (long)((ulong)_v[5] >> 63);

                /**        G (r, 5, 1, 6, 11, 12); */

                _v[1] = _v[1] + _v[6] + _m[_sig_g50[r]];
                _v[12] ^= _v[1];
                //_v[12] = (_v[12] << 32) | (_v[12] >>> 32);
                _v[12] = (_v[12] << 32) | (long)((ulong)_v[12] >> 32);
                _v[11] = _v[11] + _v[12];
                _v[6] ^= _v[11];
                //_v[6] = (_v[6] >>> 24) | (_v[6] << 40);
                _v[6] = (long)((ulong)_v[6] >> 24) | (_v[6] << 40);
                _v[1] = _v[1] + _v[6] + +_m[_sig_g51[r]];
                _v[12] ^= _v[1];
                //_v[12] = (_v[12] >>> 16) | (_v[12] << 48);
                _v[12] = (long)((ulong)_v[12] >> 16) | (_v[12] << 48);
                _v[11] = _v[11] + _v[12];
                _v[6] ^= _v[11];
                //_v[6] = (_v[6] << 1) | (_v[6] >>> 63);
                _v[6] = (_v[6] << 1) | (long)((ulong)_v[6] >> 63);

                /**        G (r, 6, 2, 7,  8, 13); */

                _v[2] = _v[2] + _v[7] + _m[_sig_g60[r]];
                _v[13] ^= _v[2];
                //_v[13] = (_v[13] << 32) | (_v[13] >>> 32);
                _v[13] = (_v[13] << 32) | (long)((ulong)_v[13] >> 32);
                _v[8] = _v[8] + _v[13];
                _v[7] ^= _v[8];
                //_v[7] = (_v[7] >>> 24) | (_v[7] << 40);
                _v[7] = (long)((ulong)_v[7] >> 24) | (_v[7] << 40);
                _v[2] = _v[2] + _v[7] + _m[_sig_g61[r]];
                _v[13] ^= _v[2];
                //_v[13] = (_v[13] >>> 16) | (_v[13] << 48);
                _v[13] = (long)((ulong)_v[13] >> 16) | (_v[13] << 48);
                _v[8] = _v[8] + _v[13];
                _v[7] ^= _v[8];
                //_v[7] = (_v[7] << 1) | (_v[7] >>> 63);
                _v[7] = (_v[7] << 1) | (long)((ulong)_v[7] >> 63);

                /**        G (r, 7, 3, 4,  9, 14); */

                _v[3] = _v[3] + _v[4] + _m[_sig_g70[r]];
                _v[14] ^= _v[3];
                //_v[14] = (_v[14] << 32) | (_v[14] >>> 32);
                _v[14] = (_v[14] << 32) | (long)((ulong)_v[14] >> 32);
                _v[9] = _v[9] + _v[14];
                _v[4] ^= _v[9];
                //_v[4] = (_v[4] >>> 24) | (_v[4] << 40);
                _v[4] = (long)((ulong)_v[4] >> 24) | (_v[4] << 40);
                _v[3] = _v[3] + _v[4] + _m[_sig_g71[r]];
                _v[14] ^= _v[3];
                //_v[14] = (_v[14] >>> 16) | (_v[14] << 48);
                _v[14] = (long)((ulong)_v[14] >> 16) | (_v[14] << 48);
                _v[9] = _v[9] + _v[14];
                _v[4] ^= _v[9];
                //_v[4] = (_v[4] << 1) | (_v[4] >>> 63);
                _v[4] = (_v[4] << 1) | ((long)((ulong)_v[4] >> 63));
            }

            // Update state vector _h
            _h[0] ^= _v[0] ^ _v[8];
            _h[1] ^= _v[1] ^ _v[9];
            _h[2] ^= _v[2] ^ _v[10];
            _h[3] ^= _v[3] ^ _v[11];
            _h[4] ^= _v[4] ^ _v[12];
            _h[5] ^= _v[5] ^ _v[13];
            _h[6] ^= _v[6] ^ _v[14];
            _h[7] ^= _v[7] ^ _v[15];

            //			Debug.dumpArray("_v @ compress end", _v);
            //			Debug.dumpArray("_h @ compress end", _h);
            /* kaamil */
        }
    }
}
