using Argon2_KDF.model;
using System.Threading.Tasks;

namespace Argon2_KDF.algorithm
{
    public class FillMemory
    {
        public static void Fill(Instance instance) {
            if (instance.GetLanes() == 1) {
                FillSingleThreaded(instance);
            }
            else {
                FillMultiThreaded(instance);
            }
        }

        private static void FillSingleThreaded(Instance instance) {
            for (int i = 0; i < instance.GetIterations(); i++) {
                for (int j = 0; j < Constants.ARGON2_SYNC_POINTS; j++) {
                    Position position = new Position(i, 0, j, 0);
                    FillSegment.Fill(instance, position);
                }
            }
        }

        private static void FillMultiThreaded(Instance instance) {
            for (int i = 0; i < instance.GetIterations(); i++) {
                for (int j = 0; j < Constants.ARGON2_SYNC_POINTS; j++) {
                    for (int k = 0; k < instance.GetLanes(); k++) {
                        int i1 = i;
                        int j1 = j;
                        int k1 = k;
                        Position position = new Position(i1, k1, j1, 0);
                        Parallel.Invoke(() => FillSegment.Fill(instance, position));
                    }
                }
            }
        }
    }
}
