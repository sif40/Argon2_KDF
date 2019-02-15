using Argon2_KDF.model;
using System;

namespace Argon2_KDF.algorithm
{
    public class Initializer
    {
        public static void Initialize(Instance instance, Argon2 argon2) {
            byte[] initialHash = Functions.InitialHash(
                    Util.IntToLittleEndianBytes(argon2.GetLanes()),
                    Util.IntToLittleEndianBytes(argon2.GetOutputLength()),
                    Util.IntToLittleEndianBytes(argon2.GetMemory()),
                    Util.IntToLittleEndianBytes(argon2.GetIterations()),
                    Util.IntToLittleEndianBytes(argon2.GetVersion()),
                    //Util.IntToLittleEndianBytes(argon2.GetType().Ordinal()),
                    Util.IntToLittleEndianBytes((int)argon2.GetType()),
                    Util.IntToLittleEndianBytes(argon2.GetPasswordLength()),
                    argon2.GetPassword(),
                    Util.IntToLittleEndianBytes(argon2.GetSaltLength()),
                    argon2.GetSalt(),
                    Util.IntToLittleEndianBytes(argon2.GetSecretLength()),
                    argon2.GetSecret(),
                    Util.IntToLittleEndianBytes(argon2.GetAdditionalLength()),
                    argon2.GetAdditional()
            );
            FillFirstBlocks(instance, initialHash);
        }

        /**
         * (H0 || 0 || i) 72 byte -> 1024 byte
         * (H0 || 1 || i) 72 byte -> 1024 byte
         */
        private static void FillFirstBlocks(Instance instance, byte[] initialHash) {

            byte[] zeroBytes = { 0, 0, 0, 0 };
            byte[] oneBytes = { 1, 0, 0, 0 };

            byte[] initialHashWithZeros = GetInitialHashLong(initialHash, zeroBytes);
            byte[] initialHashWithOnes = GetInitialHashLong(initialHash, oneBytes);

            for (int i = 0; i < instance.GetLanes(); i++) {

                byte[] iBytes = Util.IntToLittleEndianBytes(i);

                Array.Copy(iBytes, 0, initialHashWithZeros, Constants.ARGON2_PREHASH_DIGEST_LENGTH + 4, 4);
                Array.Copy(iBytes, 0, initialHashWithOnes, Constants.ARGON2_PREHASH_DIGEST_LENGTH + 4, 4);

                byte[] blockhashBytes = Functions.Blake2bLong(initialHashWithZeros, Constants.ARGON2_BLOCK_SIZE);
                instance.GetMemory()[(i * instance.GetLaneLength()) + 0].FromBytes(blockhashBytes);

                blockhashBytes = Functions.Blake2bLong(initialHashWithOnes, Constants.ARGON2_BLOCK_SIZE);
                if (instance.GetMemory().Length > (i * instance.GetLaneLength()) + 1)
                    instance.GetMemory()[(i * instance.GetLaneLength()) + 1].FromBytes(blockhashBytes);
            }
        }

        private static byte[] GetInitialHashLong(byte[] initialHash, byte[] appendix) {
            byte[] initialHashLong = new byte[Constants.ARGON2_PREHASH_SEED_LENGTH];

            Array.Copy(initialHash, 0, initialHashLong, 0, Constants.ARGON2_PREHASH_DIGEST_LENGTH);
            Array.Copy(appendix, 0, initialHashLong, Constants.ARGON2_PREHASH_DIGEST_LENGTH, 4);

            return initialHashLong;
        }
    }
}
