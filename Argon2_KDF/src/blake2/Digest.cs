namespace Argon2_KDF.blake2
{
    // ---------------------------------------------------------------------
    // Blake2b Message Digest
    // ---------------------------------------------------------------------

    /** Generalized Blake2b digest. */
    public class Digest : Engine
    {
        private Digest(Param p) : base(p) { }
        private Digest() : base() { }

        public static Digest NewInstance() => new Digest();

        public static Digest NewInstance(int digestLength) => new Digest(new Param().SetDigestLength(digestLength));

        public static Digest NewInstance(Param p) => new Digest(p);
    }
}
