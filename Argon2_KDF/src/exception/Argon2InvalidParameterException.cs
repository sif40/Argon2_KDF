using System;

namespace Argon2_KDF.exception
{
    public class Argon2InvalidParameterException : AccessViolationException
    {
        public Argon2InvalidParameterException(string message) : base(message) {

        }
    }
}
