namespace Argon2_KDF.model
{
    public class Instance
    {
        private Block[] _memory;
        private readonly int _version;
        private readonly int _iterations;
        private readonly int _segmentLength;
        private readonly int _laneLength;
        private readonly int _lanes;
        private readonly Argon2Type _type;

        public Instance(Argon2 argon2) {
            _version = argon2.GetVersion();
            _iterations = argon2.GetIterations();
            _lanes = argon2.GetLanes();
            _type = argon2.GetType();

            /* 2. Align _memory size */
            /* Minimum memoryBlocks = 8L blocks, where L is the number of _lanes */
            int memoryBlocks = argon2.GetMemory();

            if (memoryBlocks < 2 * Constants.ARGON2_SYNC_POINTS * argon2.GetLanes()) {
                memoryBlocks = 2 * Constants.ARGON2_SYNC_POINTS * argon2.GetLanes();
            }

            _segmentLength = memoryBlocks / (argon2.GetLanes() * Constants.ARGON2_SYNC_POINTS);
            _laneLength = _segmentLength * Constants.ARGON2_SYNC_POINTS;
            /* Ensure that all segments have equal length */
            memoryBlocks = _segmentLength * (argon2.GetLanes() * Constants.ARGON2_SYNC_POINTS);

            InitMemory(memoryBlocks);
        }

        private void InitMemory(int memoryBlocks) {
            _memory = new Block[memoryBlocks];

            for (int i = 0; i < _memory.Length; i++) {
                _memory[i] = new Block();
            }
        }

        public void Clear() {
            foreach (Block b in _memory) {
                b.Clear();
            }

            _memory = null;
        }

        public Block[] GetMemory() => _memory;

        public int GetVersion() => _version;

        public int GetIterations() => _iterations;

        public int GetSegmentLength() => _segmentLength;

        public int GetLaneLength() => _laneLength;

        public int GetLanes() => _lanes;

        public new Argon2Type GetType() => _type;
    }
}
