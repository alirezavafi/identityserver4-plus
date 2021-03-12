using System.ComponentModel.DataAnnotations;

namespace SSO.Models
{
    public class SelectUserModel
    {
        [Required]
        [StringLength(2048)]
        public string ReturnUrl { get; set; }
        [StringLength(30)]
        public string Username { get; set; }
    }
}
