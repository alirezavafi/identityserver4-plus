using System.ComponentModel.DataAnnotations;
using System.Net;

namespace SSO.Models
{
    public class LoginModel
    {
        private string otpCode;
        private string mobileNumber;
        private string visitorCode;

        [Required]
        [StringLength(15)]
        public string MobileNumber { get => mobileNumber; set => mobileNumber = value.ConvertEnglishChar(); }
        [Required]
        [StringLength(10)]
        public string OtpCode { get => otpCode; set => otpCode = value.ConvertEnglishChar().RemoveStartingZeroIfExists(); }
        [Required]
        [StringLength(2048)]
        public string ReturnUrl { get; set; }
        [StringLength(2048)]
        public string VisitorCode
        {
            get => visitorCode; 
            set
            {
                visitorCode = GetCorrectVisitorCode(value);
            }
        }

        private string GetCorrectVisitorCode(string visitorCode)
        {
            return WebUtility.UrlDecode(visitorCode)?.Replace("\"", "")?.ConvertEnglishChar();
        }


        [StringLength(2048)]
        public string Referrer { get; set; }
    }
}
