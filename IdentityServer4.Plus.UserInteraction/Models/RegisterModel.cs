using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using DNTPersianUtils.Core;

namespace SSO.Models
{
    public class RegisterResult
    {
        public bool IsSucceed { get; set; }
        public string ErrorMessage { get; set; }
    }

    public class RegisterModel
    {
        private string nationalCode;

        [ValidIranianNationalCode]
        public string NationalCode { get => nationalCode; set => nationalCode = value.ConvertEnglishChar(); }
        [Required]
        [StringLength(50)]
        public string FirstName { get; set; }
        [Required]
        [StringLength(50)]
        public string LastName { get; set; }
        [EmailAddress]
        public string Email { get; set; }
        [StringLength(50)]
        public string Password { get; set; }
        [Required]
        [StringLength(2048)]
        public string ReturnUrl { get; set; }
    }
}
