using System;
using System.Text;

namespace CoreLib.Services.Otp
{
    public class OtpService : IOtpService
    {
        private Rfc6238AuthenticationService generator;

        public OtpService()
        {
           generator = new Rfc6238AuthenticationService();
        }

        public string GenerateOtp(string mobileNumber, string securityToken = null)
        {
            if (string.IsNullOrWhiteSpace(mobileNumber) || mobileNumber.Length < 10)
            {
                throw new ArgumentException(nameof(mobileNumber));
            }

            var secToken = securityToken == null ? GenerateSecurityToken(mobileNumber) : GetSecurityToken(securityToken);
            return generator.GenerateCode(secToken).ToString("000000");
        }

        public bool IsValidOtp(string mobileNumber, string otpCode, string securityToken = null)
        {
            if (string.IsNullOrWhiteSpace(mobileNumber) || mobileNumber.Length < 10)
            {
                throw new ArgumentException(nameof(mobileNumber));
            }
            int otp;
            if (!int.TryParse(otpCode, out otp))
            {
                throw new ArgumentException(nameof(otpCode));
            }

            var secToken = securityToken == null ? GenerateSecurityToken(mobileNumber) : GetSecurityToken(securityToken);
            return generator.ValidateCode(secToken, otp);
        }

        private SecurityToken GenerateSecurityToken(string mobileNumber)
        {
            return new SecurityToken(Encoding.Unicode.GetBytes(mobileNumber + "!@#^)" + mobileNumber.Substring(5)));
        }

        private SecurityToken GetSecurityToken(string text)
        {
            return new SecurityToken(Encoding.Unicode.GetBytes(text));
        }
    }
}
