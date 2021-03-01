using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

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

        [StringLength(10, MinimumLength = 10)]
        public string NationalCode { get => nationalCode; set => nationalCode = value.ConvertEnglishChar(); }
        [Required]
        [StringLength(50)]
        public string FirstName { get; set; }
        [Required]
        [StringLength(50)]
        public string LastName { get; set; }
        [Required]
        [StringLength(2048)]
        public string ReturnUrl { get; set; }
    }
}
