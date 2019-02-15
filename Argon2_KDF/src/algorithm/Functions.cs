using Argon2_KDF.model;
using System;
using Argon2_KDF.blake2;

namespace Argon2_KDF.algorithm
{
    public class Functions
    {
        /**
         * H0 = H64(p, Ï„, m, t, v, y, |P|, P, |S|, S, |L|, K, |X|, X)
         * -> 64 byte (ARGON2_PREHASH_DIGEST_LENGTH)
        */
        public static byte[] InitialHash(byte[] lanes, byte[] outputLength,
                                         byte[] memory, byte[] iterations,
                                         byte[] version, byte[] type,
                                         byte[] passwordLength, byte[] password,
                                         byte[] saltLength, byte[] salt,
                                         byte[] secretLength, byte[] secret,
                                         byte[] additionalLength, byte[] additional) {


            Param param = new Param().SetDigestLength(Constants.ARGON2_PREHASH_DIGEST_LENGTH);

            //IBlake2b blake2b = Engine.Digest.NewInstance(param);
            IBlake2b blake2b = Digest.NewInstance(param);

            blake2b.Update(lanes);
            blake2b.Update(outputLength);
            blake2b.Update(memory);
            blake2b.Update(iterations);
            blake2b.Update(version);
            blake2b.Update(type);

            blake2b.Update(passwordLength);
            if (password != null) {
                blake2b.Update(password);
            }

            blake2b.Update(saltLength);
            if (salt != null) {
                blake2b.Update(salt);
            }

            blake2b.Update(secretLength);
            if (secret != null) {
                blake2b.Update(secret);
            }

            blake2b.Update(additionalLength);
            if (additional != null) {
                blake2b.Update(additional);
            }

            byte[] blake2hash = blake2b.Digest();

            return blake2hash;
        }


        /**
         * H' - blake2bLong - variable length hash function
         */
        public static byte[] Blake2bLong(byte[] input, int outputLength) {
            byte[] result = new byte[outputLength];
            byte[] outlenBytes = Util.IntToLittleEndianBytes(outputLength);

            int blake2bLength = 64;

            if (outputLength <= blake2bLength) {
                result = Blake2b(input, outlenBytes, outputLength);
            }
            else {
                byte[] outBuffer;

                /* V1 */
                outBuffer = Blake2b(input, outlenBytes, blake2bLength);
                Array.Copy(outBuffer, 0, result, 0, blake2bLength / 2);

                int r = (outputLength / 32) + (outputLength % 32 == 0 ? 0 : 1) - 2;

                int position = blake2bLength / 2;
                for (int i = 2; i <= r; i++, position += blake2bLength / 2) {
                    /* V2 to Vr */
                    outBuffer = Blake2b(outBuffer, null, blake2bLength);
                    Array.Copy(outBuffer, 0, result, position, blake2bLength / 2);
                }

                int lastLength = outputLength - (32 * r);

                /* Vr+1 */
                outBuffer = Blake2b(outBuffer, null, lastLength);
                Array.Copy(outBuffer, 0, result, position, lastLength);
            }

            return result;
        }

        private static byte[] Blake2b(byte[] input, byte[] outlenBytes, int outputLength) {
            Param param = new Param().SetDigestLength(outputLength);

            //IBlake2b blake2b = Blake2b.Digest.NewInstance(param);
            IBlake2b blake2b = Digest.NewInstance(param);

            if (outlenBytes != null)
                blake2b.Update(outlenBytes);

            blake2b.Update(input);

            return blake2b.Digest();
        }

        public static void RoundFunction(Block block,
                                  int v0, int v1, int v2, int v3,
                                  int v4, int v5, int v6, int v7,
                                  int v8, int v9, int v10, int v11,
                                  int v12, int v13, int v14, int v15) {

            F(block, v0, v4, v8, v12);
            F(block, v1, v5, v9, v13);
            F(block, v2, v6, v10, v14);
            F(block, v3, v7, v11, v15);

            F(block, v0, v5, v10, v15);
            F(block, v1, v6, v11, v12);
            F(block, v2, v7, v8, v13);
            F(block, v3, v4, v9, v14);
        }

        private static void F(Block block, int a, int b, int c, int d) {
            FBlaMka(block, a, b);
            Rotr64(block, d, a, 32);

            FBlaMka(block, c, d);
            Rotr64(block, b, c, 24);

            FBlaMka(block, a, b);
            Rotr64(block, d, a, 16);

            FBlaMka(block, c, d);
            Rotr64(block, b, c, 63);
        }

        /*designed by the Lyra PHC team */
        /* a <- a + b + 2*aL*bL
         * + == addition modulo 2^64
         * aL = least 32 bit */
        private static void FBlaMka(Block block, int x, int y) {
            long m = 0xFFFFFFFFL;
            long xy = (block.v[x] & m) * (block.v[y] & m);

            block.v[x] = block.v[x] + block.v[y] + 2 * xy;
        }

        private static void Rotr64(Block block, int v, int w, long c) {
            long temp = block.v[v] ^ block.v[w];
            //block.v[v] = (temp >>> c) | (temp << (64 - c));
            block.v[v] = (long)((ulong)temp >> (int)c) | (temp << (int)(64 - c));
        }
    }
}
