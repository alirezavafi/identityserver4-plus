using System.ComponentModel.DataAnnotations;
using System.Net;
using Persian.Plus.Core.DataAnnotations;
using Persian.Plus.Core.Extensions;

namespace SSO.Models
{
    public class LoginByOtpModel
    {
        private string otpCode;
        private string mobileNumber;

        [Required]
        [IranianMobileNumber]
        public string MobileNumber { get => mobileNumber; set => mobileNumber = value.ToEnglishNumbers(); }
        [Required]
        [StringLength(10)]
        public string OtpCode { get => otpCode; set => otpCode = value.ToEnglishNumbers().RemoveStartingZeroIfExists(); }
        [Required]
        [StringLength(2048)]
        public string ReturnUrl { get; set; }
        
        [StringLength(2048)]
        public string Referrer { get; set; }
    }
}
