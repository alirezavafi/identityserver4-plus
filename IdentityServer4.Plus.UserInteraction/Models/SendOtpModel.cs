using System.ComponentModel.DataAnnotations;

namespace SSO.Models
{
    public class SendOtpModel
    {
        private string mobileNumber;
        private string visitorCode;

        [Required]
        [StringLength(15)]
        public string MobileNumber { get => mobileNumber; set => mobileNumber = value.ConvertEnglishChar(); }
        [Required]
        [StringLength(2048)]
        public string ReturnUrl { get; set; }
        [StringLength(2048)]
        public string VisitorCode { get => visitorCode; set => visitorCode = value.ConvertEnglishChar(); }
        [StringLength(2048)]
        public string Referrer { get; set; }
    }
}
