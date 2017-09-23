using System;
using System.Globalization;
using System.Text;
using PwSafeLib.Filesystem;

namespace PwSafeLib.Passwords
{
    [Flags]
    public enum PwPolicyFlags
    {
        None = 0,
        UseLowercase = 0x8000, // Can have a minimum length field
        UseUppercase = 0x4000, // Can have a minimum length field
        UseDigits = 0x2000, // Can have a minimum length field
        UseSymbols = 0x1000, // Can have a minimum length field
        UseHexDigits = 0x0800,
        UseEasyVision = 0x0400,
        MakePronounceable = 0x0200,
        Unused = 0x01ff
    }

    /// <summary>
    /// Represents a password policy. This can be added to <see cref="PwsFile.PasswordPolicies"/>.
    /// </summary>
    public class PwPolicy
    {
        private const int PolStrEncLen = 19;

        /// <summary>
        /// Creates a new empty policy.
        /// </summary>
        public PwPolicy() { }

        /// <summary>
        /// Deserializes a policy from a string created with <see cref="ToString"/>.
        /// </summary>
        /// <param name="str"></param>
        public PwPolicy(string str)
        {
            if (string.IsNullOrEmpty(str) || str.Length != PolStrEncLen)
            {
                Symbols = "";
                return;
            }

            // String !empty and of right length: Get fields
            Flags = (PwPolicyFlags)ParseHex(str, 0, 4);
            Length = ParseHex(str, 4, 3);
            DigitMinLength = ParseHex(str, 7, 3);
            LowerMinLength = ParseHex(str, 10, 3);
            SymbolMinLength = ParseHex(str, 13, 3);
            UpperMinLength = ParseHex(str, 16, 3);
        }

        private static int ParseHex(string s, int index, int len)
        {
            return int.Parse(s.Substring(index, len), NumberStyles.AllowHexSpecifier);
        }

        public PwPolicyFlags Flags { get; set; }

        // Following are limited by format to 2-byte values,
        // but changing int to uint16 is unwarranted, too much ugliness.
        public int Length { get; set; }

        public int DigitMinLength { get; set; }

        public int LowerMinLength { get; set; }

        public int SymbolMinLength { get; set; }

        public int UpperMinLength { get; set; }

        /// <summary>
        /// Policy-specific set of 'symbol' characters
        /// </summary>
        public string Symbols { get; set; }

        /// <summary>
        /// How many entries use this policy?
        /// </summary>
        public int UseCount { get; set; }


        /// <summary>
        /// Creates a random password using the policy.
        /// </summary>
        /// <param name="fallbackPolicy">Policy to use, if <see cref="Flags"/> is <see cref="PwPolicyFlags.None"/>.</param>
        /// <returns>A new random password.</returns>
        public string MakeRandomPassword(PwPolicy fallbackPolicy)
        {
            var policy = this;
            if (Flags == PwPolicyFlags.None)
            {
                policy = fallbackPolicy;
            }
            var pcp = new PasswordCharPool(policy);
            return pcp.MakePassword();
        }

        public string DisplayString
        {
            get
            {
                if (Flags != PwPolicyFlags.None)
                {
                    var pwp = new StringBuilder();
                    if (Flags.HasFlag(PwPolicyFlags.UseLowercase))
                    {
                        pwp.Append("L");
                        if (LowerMinLength > 1)
                        {
                            pwp.Append($"({LowerMinLength})");
                        }
                    }
                    if (Flags.HasFlag(PwPolicyFlags.UseUppercase))
                    {
                        pwp.Append("U");
                        if (UpperMinLength > 1)
                        {
                            pwp.Append($"({UpperMinLength})");
                        }
                    }
                    if (Flags.HasFlag(PwPolicyFlags.UseDigits))
                    {
                        pwp.Append("D");
                        if (UpperMinLength > 1)
                        {
                            pwp.Append($"({DigitMinLength})");
                        }
                    }
                    if (Flags.HasFlag(PwPolicyFlags.UseSymbols))
                    {
                        pwp.Append("S");
                        if (UpperMinLength > 1)
                        {
                            pwp.Append($"({SymbolMinLength})");
                        }
                    }
                    if (Flags.HasFlag(PwPolicyFlags.UseHexDigits))
                    {
                        pwp.Append("H");
                    }
                    if (Flags.HasFlag(PwPolicyFlags.UseEasyVision))
                    {
                        pwp.Append("E");
                    }
                    if (Flags.HasFlag(PwPolicyFlags.MakePronounceable))
                    {
                        pwp.Append("P");
                    }
                    pwp.Append($":{Length}");
                    return pwp.ToString();
                }
                return "";
            }
        }

        public override string ToString()
        {

            if (Flags == PwPolicyFlags.None)
            {
                return "";
            }

            var oss = new StringBuilder();
            void WriteHex(int value, int chars = 3)
            {
                oss.AppendFormat("{0:x" + chars + "}", value);
            }

            WriteHex((int)Flags, 4);
            WriteHex(Length);
            WriteHex(DigitMinLength);
            WriteHex(LowerMinLength);
            WriteHex(SymbolMinLength);
            WriteHex(UpperMinLength);

            return oss.ToString();
        }
    }
}
