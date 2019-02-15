namespace Argon2_KDF.blake2
{
    public interface IBlake2b
    {
        void Update(byte[] input);

        void Update(byte input);

        void Update(byte[] input, int offset, int len);

        byte[] Digest();

        byte[] Digest(byte[] input);

        void Digest(byte[] output, int offset, int len);

        void Reset();
    }
}
