using System.ComponentModel.DataAnnotations;
using Persian.Plus.Core.Extensions;

namespace SSO.Models
{
    public class SendOtpModel
    {
        private string mobileNumber;

        [Required]
        [StringLength(15)]
        public string MobileNumber { get => mobileNumber; set => mobileNumber = value.ToEnglishNumbers(); }
        [Required]
        [StringLength(2048)]
        public string ReturnUrl { get; set; }
        [StringLength(2048)]
        public string Referrer { get; set; }
    }
}
