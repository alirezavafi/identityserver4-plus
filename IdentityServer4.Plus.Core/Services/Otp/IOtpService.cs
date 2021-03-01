namespace CoreLib.Services.Otp
{
    public interface IOtpService
    {
        string GenerateOtp(string mobileNumber, string securityToken = null);
        bool IsValidOtp(string mobileNumber, string otpCode, string securityToken = null);
    }
}