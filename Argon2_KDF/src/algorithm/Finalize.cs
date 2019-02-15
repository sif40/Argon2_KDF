using Argon2_KDF.model;

namespace Argon2_KDF.algorithm
{
    public class Finalizer
    {
        public static void Finalize(Instance instance, Argon2 argon2) {

            Block finalBlock = instance.GetMemory()[instance.GetLaneLength() - 1];

            /* XOR the last blocks */
            for (int i = 1; i < instance.GetLanes(); i++) {
                int lastBlockInLane = (i * instance.GetLaneLength()) + (instance.GetLaneLength() - 1);
                finalBlock.XorWith(instance.GetMemory()[lastBlockInLane]);
            }

            byte[] finalBlockBytes = finalBlock.ToBytes();
            byte[] finalResult = Functions.Blake2bLong(finalBlockBytes, argon2.GetOutputLength());

            argon2.SetOutput(finalResult);

            if (argon2.IsClearMemory()) {
                instance.Clear();
                argon2.Clear();
            }
        }
    }
}
