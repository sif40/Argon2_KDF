namespace Argon2_KDF.blake2
{
    // ---------------------------------------------------------------------
    // Blake2b Incremental Message Digest (Tree)
    // ---------------------------------------------------------------------

    /**
     *  Note that Tree is just a convenience class; incremental hash (tree)
     *  can be done directly with the Digest class.
     *  <br>
     *  Further node, that tree does NOT accumulate the leaf hashes --
     *  you need to do that
     */
    public class Tree
    {

        readonly int depth;
        readonly int fanout;
        readonly int leaf_length;
        readonly int inner_length;
        readonly int digest_length;

        /**
         *
         * @param fanout
         * @param depth
         * @param leaf_length size of data input for leaf nodes.
         * @param inner_length note this is used also as digest-length for non-root nodes.
         * @param digest_length final hash out digest-length for the tree
         */
        public Tree(int depth, int fanout,
                    int leaf_length, int inner_length,
                    int digest_length) {
            this.fanout = fanout;
            this.depth = depth;
            this.leaf_length = leaf_length;
            this.inner_length = inner_length;
            this.digest_length = digest_length;
        }

        private Param TreeParam() {
            return new Param().
                SetDepth(depth).SetFanout(fanout).SetLeafLength(leaf_length).SetInnerLength(inner_length);
        }

        /** returns the Digest for tree node @ (depth, offset) */
        public Digest GetNode(int depth, int offset) {
            Param nodeParam = TreeParam().SetNodeDepth(depth).SetNodeOffset(offset).SetDigestLength(inner_length);
            return Digest.NewInstance(nodeParam);
        }

        /** returns the Digest for root node */
        public Digest GetRoot() {
            int depth = this.depth - 1;
            Param rootParam = TreeParam().SetNodeDepth(depth).SetNodeOffset(0L).SetDigestLength(digest_length);
            return Digest.NewInstance(rootParam);
        }
    }
}
