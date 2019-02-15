namespace Argon2_KDF.blake2
{
    // ---------------------------------------------------------------------
    // Blake2b Message Authentication Code
    // ---------------------------------------------------------------------

    /** Message Authentication Code (MAC) digest. */
    public class Mac : Engine, IBlake2b
    {

        private Mac(Param p) : base(p) { }
        private Mac() : base() { }

        /** Blake2b.MAC 512 - using default Blake2b.Spec settings with given key */
        public static Mac NewInstance(byte[] key) => new Mac(new Param().SetKey(key));

        /** Blake2b.MAC - using default Blake2b.Spec settings with given key, with given digest length */
        public static Mac NewInstance(byte[] key, int digestLength) => new Mac(new Param().SetKey(key).SetDigestLength(digestLength));

        /** Blake2b.MAC - using default Blake2b.Spec settings with given java.security.Key, with given digest length */
        //public static Mac NewInstance(Key key, int digestLength) => new Mac(new Param().SetKey(key).SetDigestLength(digestLength));

        /** Blake2b.MAC - using the specified Parameters.
         * @param p asserted valid configured Param with key */
        public static Mac NewInstance(Param p) => new Mac(p);
    }
}
