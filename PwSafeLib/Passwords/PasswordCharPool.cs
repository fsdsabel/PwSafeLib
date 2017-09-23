using System;
using System.Collections.Generic;
using System.Text;

namespace PwSafeLib.Passwords
{
    public enum PasswordErrors
    {
        None,
        PasswordTooShort,
        PoorPassword
    }

    /// <summary>
    /// This class is used to create a random password based on the policy
    ///  defined in the constructor.
    ///  The class ensures that if a character type is selected, then at least one
    ///  character from that type will be in the generated password. (i.e., at least
    ///  one digit if usedigits is set in the constructor).
    /// 
    ///  The usage scenario is something like:
    ///  PasswordCharPool pwgen = new PasswordCharPool(policy);
    ///  StringX pwd = pwgen.MakePassword();
    /// 
    ///  <see cref="CheckPassword"/> is used to verify the strength of existing passwords,
    ///  i.e., the password used to protect the database.
    /// </summary>
    public class PasswordCharPool
    {
        public PasswordCharPool(PwPolicy policy)
        {
            
        }

        public string MakePassword()
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Checks a password for "good enough".
        /// </summary>
        /// <param name="pwd">Password to check.</param>
        /// <param name="error">The error of the password, if return value is false.</param>
        /// <returns>true, if password is good</returns>
        public static bool CheckPassword(string pwd, out PasswordErrors error)
        {
          /**
           * A password is "Good enough" if:
           * It is at least SufficientLength characters long
           * OR
           * It is at least MinLength characters long AND it has
           * at least one uppercase and one lowercase and one (digit or other).
           *
           * A future enhancement of this might be to calculate the Shannon Entropy
           * in combination with a minimum password length.
           * http://rosettacode.org/wiki/Entropy
           */

            error = PasswordErrors.None;
            const int sufficientLength = 12;
            const int minLength = 8;
            var length = pwd.Length;

            if (length >= sufficientLength)
            {
                return true;
            }

            if (length < minLength)
            {
                error = PasswordErrors.PasswordTooShort;
                return false;
            }

            // check for at least one uppercase and lowercase and one (digit or other)
            bool hasUc = false, hasLc = false, hasDigit = false, hasOther = false;
            foreach (var c in pwd)
            {
                if (char.IsLower(c)) hasLc = true;
                else if (char.IsUpper(c)) hasUc = true;
                else if (char.IsDigit(c)) hasDigit = true;
                else hasOther = true;
            }
            if (hasUc && hasLc && (hasDigit || hasOther))
            {
                return true;
            }
            error = PasswordErrors.PoorPassword;
            return false;
        }
    }
}
