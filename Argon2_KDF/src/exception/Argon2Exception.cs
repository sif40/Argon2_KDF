using System;

namespace Argon2_KDF.exception
{
    public class Argon2Exception : SystemException
    {
        Argon2Exception(string message) : base(message) {
        }
    }
}
