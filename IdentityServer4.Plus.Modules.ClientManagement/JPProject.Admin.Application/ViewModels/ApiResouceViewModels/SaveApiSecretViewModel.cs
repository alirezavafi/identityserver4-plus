using System;
using System.ComponentModel.DataAnnotations;
using JPProject.Admin.Domain.Commands;

namespace JPProject.Admin.Application.ViewModels.ApiResouceViewModels
{
    public class SaveApiSecretViewModel
    {
        public string Description { get; set; }
        [Required]
        public string Value { get; set; }
        public DateTime? Expiration { get; set; }
        [Required]
        public HashType? Hash { get; set; } = 0;
        [Required]
        public string Type { get; set; }

        public string ResourceName { get; set; }
    }
}