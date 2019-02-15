using Argon2_KDF.model;

namespace Argon2_KDF.algorithm
{
    public class FillSegment
    {
        public static void Fill(Instance instance, Position position) {
            Block addressBlock = null, inputBlock = null, zeroBlock = null;

            bool dataIndependentAddressing = IsDataIndependentAddressing(instance, position);
            int startingIndex = GetStartingIndex(position);
            int currentOffset = 
                (position.lane * instance.GetLaneLength()) + (position.slice * instance.GetSegmentLength()) + startingIndex;
            int prevOffset = GetPrevOffset(instance, currentOffset);

            if (dataIndependentAddressing) {
                addressBlock = new Block();
                zeroBlock = new Block();
                inputBlock = new Block();

                InitAddressBlocks(instance, position, zeroBlock, inputBlock, addressBlock);
            }

            for (position.index = startingIndex; 
                 position.index < instance.GetSegmentLength(); 
                 position.index++, currentOffset++, prevOffset++) {
                prevOffset = RotatePrevOffset(instance, currentOffset, prevOffset);

                long pseudoRandom = 
                    GetPseudoRandom(instance, position, addressBlock, inputBlock, zeroBlock, prevOffset, dataIndependentAddressing);
                int refLane = GetRefLane(instance, position, pseudoRandom);
                int refColumn = GetRefColumn(instance, position, pseudoRandom, refLane == position.lane);

                /* 2 Creating a new block */
                Block prevBlock = instance.GetMemory()[prevOffset];
                Block refBlock = instance.GetMemory()[(instance.GetLaneLength() * refLane) + refColumn];
                Block currentBlock = instance.GetMemory()[currentOffset];

                bool withXor = IsWithXor(instance, position);
                FillBlock.Fill(prevBlock, refBlock, currentBlock, withXor);
            }
        }

        private static bool IsDataIndependentAddressing(Instance instance, Position position) {
            return (instance.GetType() == Argon2Type.Argon2i) || 
                   (instance.GetType() == Argon2Type.Argon2id
                    && (position.pass == 0)
                    && (position.slice < Constants.ARGON2_SYNC_POINTS / 2));
        }

        private static void InitAddressBlocks(Instance instance, Position position, 
                                              Block zeroBlock, Block inputBlock, 
                                              Block addressBlock) {
            inputBlock.v[0] = Util.IntToLong(position.pass);
            inputBlock.v[1] = Util.IntToLong(position.lane);
            inputBlock.v[2] = Util.IntToLong(position.slice);
            inputBlock.v[3] = Util.IntToLong(instance.GetMemory().Length);
            inputBlock.v[4] = Util.IntToLong(instance.GetIterations());
            //inputBlock.v[5] = Util.IntToLong(instance.GetType().Ordinal());
            inputBlock.v[5] = Util.IntToLong((int)instance.GetType());

            if ((position.pass == 0) && (position.slice == 0)) {
                /* Don't forget to generate the first block of addresses: */
                NextAddresses(zeroBlock, inputBlock, addressBlock);
            }
        }

        private static bool IsWithXor(Instance instance, Position position) 
            => !(position.pass == 0 || instance.GetVersion() == Constants.ARGON2_VERSION_10);

        private static int GetPrevOffset(Instance instance, int currentOffset) {
            if (currentOffset % instance.GetLaneLength() == 0) {
                /* Last block in this lane */
                return currentOffset + instance.GetLaneLength() - 1;
            }
            else {
                /* Previous block */
                return currentOffset - 1;
            }
        }

        private static int RotatePrevOffset(Instance instance, int currentOffset, int prevOffset) {
            if (currentOffset % instance.GetLaneLength() == 1) {
                prevOffset = currentOffset - 1;
            }
            return prevOffset;
        }

        private static int GetStartingIndex(Position position) {
            if ((position.pass == 0) && (position.slice == 0)) {
                return 2; /* we have already generated the first two blocks */
            }
            else {
                return 0;
            }
        }

        private static void NextAddresses(Block zeroBlock, Block inputBlock, Block addressBlock) {
            inputBlock.v[6]++;
            FillBlock.Fill(zeroBlock, inputBlock, addressBlock, false);
            FillBlock.Fill(zeroBlock, addressBlock, addressBlock, false);
        }

        /* 1.2 Computing the index of the reference block */
        /* 1.2.1 Taking pseudo-random value from the previous block */
        private static long GetPseudoRandom(Instance instance, Position position, 
                                            Block addressBlock, Block inputBlock, 
                                            Block zeroBlock, int prevOffset, 
                                            bool dataIndependentAddressing) {
            if (dataIndependentAddressing) {
                if (position.index % Constants.ARGON2_ADDRESSES_IN_BLOCK == 0) {
                    NextAddresses(zeroBlock, inputBlock, addressBlock);
                }
                return addressBlock.v[position.index % Constants.ARGON2_ADDRESSES_IN_BLOCK];
            }
            else {
                return instance.GetMemory()[prevOffset].v[0];
            }
        }

        private static int GetRefLane(Instance instance, Position position, long pseudoRandom) {
            int refLane = (int)(((long)((ulong)pseudoRandom >> 32)) % instance.GetLanes());

            if ((position.pass == 0) && (position.slice == 0)) {
                /* Can not reference other lanes yet */
                refLane = position.lane;
            }
            return refLane;
        }

        private static int GetRefColumn(Instance instance, Position position, long pseudoRandom, bool sameLane) {

            int referenceAreaSize;
            int startPosition;

            if (position.pass == 0) {
                startPosition = 0;

                if (sameLane) {
                    /* The same lane => add current segment */
                    referenceAreaSize = (position.slice * instance.GetSegmentLength()) + position.index - 1;
                }
                else {
                    /* pass == 0 && !sameLane => position.slice > 0*/
                    referenceAreaSize = (position.slice * instance.GetSegmentLength()) + ((position.index == 0) ? (-1) : 0);
                }

            }
            else {
                startPosition = ((position.slice + 1) * instance.GetSegmentLength()) % instance.GetLaneLength();

                if (sameLane) {
                    referenceAreaSize = instance.GetLaneLength() - instance.GetSegmentLength() + position.index - 1;
                }
                else {
                    referenceAreaSize = instance.GetLaneLength() - instance.GetSegmentLength() + ((position.index == 0) ? (-1) : 0);
                }
            }

            long relativePosition = pseudoRandom & 0xFFFFFFFFL;
            //        long relativePosition = pseudoRandom << 32 >>> 32;
            relativePosition = (long)(ulong)(relativePosition * relativePosition) >> 32;
            relativePosition = referenceAreaSize - 1 - ((long)(ulong)(referenceAreaSize * relativePosition) >> 32);

            return (int)(startPosition + relativePosition) % instance.GetLaneLength();
        }
    }
}
