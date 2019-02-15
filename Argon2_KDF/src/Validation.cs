using Argon2_KDF.exception;

namespace Argon2_KDF
{
    public class Validation
    {
        public static void ValidateInput(Argon2 argon2) {
            string message = null;

            if (argon2.GetLanes() < Constants.Constraints.MIN_PARALLELISM)
                message = Constants.Messages.P_MIN_MSG;
            else if (argon2.GetLanes() > Constants.Constraints.MAX_PARALLELISM)
                message = Constants.Messages.P_MAX_MSG;
            else if (argon2.GetMemory() < 2 * argon2.GetLanes())
                message = Constants.Messages.M_MIN_MSG;
            else if (argon2.GetIterations() < Constants.Constraints.MIN_ITERATIONS)
                message = Constants.Messages.T_MIN_MSG;
            else if (argon2.GetIterations() > Constants.Constraints.MAX_ITERATIONS)
                message = Constants.Messages.T_MAX_MSG;
            else if (argon2.GetPasswordLength() < Constants.Constraints.MIN_PWD_LENGTH)
                message = Constants.Messages.PWD_MIN_MSG;
            else if (argon2.GetPasswordLength() > Constants.Constraints.MAX_PWD_LENGTH)
                message = Constants.Messages.PWD_MAX_MSG;
            else if (argon2.GetSaltLength() < Constants.Constraints.MIN_SALT_LENGTH)
                message = Constants.Messages.SALT_MIN_MSG;
            else if (argon2.GetSaltLength() > Constants.Constraints.MAX_SALT_LENGTH)
                message = Constants.Messages.SALT_MAX_MSG;
            else if (argon2.GetSecretLength() > Constants.Constraints.MAX_SECRET_LENGTH)
                message = Constants.Messages.SECRET_MAX_MSG;
            else if (argon2.GetAdditionalLength() > Constants.Constraints.MAX_AD_LENGTH)
                message = Constants.Messages.ADDITIONAL_MAX_MSG;

            if (message != null)
                throw new Argon2InvalidParameterException(message);
        }
    }
}
