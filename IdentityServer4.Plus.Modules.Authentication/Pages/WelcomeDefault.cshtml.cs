using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using CoreLib.Services.Otp;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Persian.Plus.Core.DataAnnotations;
using Persian.Plus.Core.Extensions;
using Serilog;
using SSO.Controllers;
using SSO.Identity;

namespace IdentityServer4.Plus.Modules.Authentication.Pages
{
    public class Welcome : PageModel
    {
        private readonly ApplicationUserManager _userManager;
        private readonly ILogger _logger;
        private readonly IOtpService _otpService;
        private readonly ISmsService _smsService;

        public Welcome(ApplicationUserManager userManager, ILogger logger, IOtpService otpService
            )
        {
            _userManager = userManager;
            _logger = logger;
            _otpService = otpService;
            //_smsService = smsService;
        }

        
        [Required]
        [StringLength(30)]
        public string Username { get; set; }
        //[Required]
        [StringLength(2048)]
        public string ReturnUrl { get; set; }
        [StringLength(2048)]
        public string Referrer { get; set; }
        
        public IActionResult OnGet()
        {
            return Page();
        }

        public async Task<IActionResult> OnPost()
        {
            if (!ModelState.IsValid)
            {
                _logger.Verbose("Invalid {@Input}", ModelState.Values);
                return Page();
            }
            //     var context = await _identityServerInteractionService.GetAuthorizationContextAsync(model.ReturnUrl);
            //     if (context == null)
            //     {
            //         _logger.Verbose("ReturnUrl invalid, cannot find authorization context", ModelState.Values);
            //         return BadRequest();
            //     }
            
            return Page();
            //     using var logContext = LogContext.PushProperty("MobileNumber", model.MobileNumber);
            //     var existingUser = await _userManager.FindFirstByPhoneNumberAsync(MobileNumber);
            //     string otpCode;
            //     if (existingUser == null)
            //     {
            //         _logger.Information("User not exists, trying to authenticate for registration", ModelState.Values);
            //         otpCode = _otpService.GenerateOtp(MobileNumber);
            //     }
            //     else
            //     {
            //         _logger.Information("User already exists, generating user otp", ModelState.Values);
            //         otpCode = await _userManager.GenerateChangePhoneNumberTokenAsync(existingUser, MobileNumber);
            //     }
            //
            //     await this.SendOtpCode(MobileNumber, otpCode);
            //     return RedirectToPage("LoginByOtp");
        }
        private async Task SendOtpCode(string mobileNumber, string otpCode)
        {
            _logger.Verbose("Sending {@Otp}", otpCode);
            await _smsService.Send(new OutgoingSms()
            {
                Reciever = mobileNumber,
                Text = $"کد فعال سازی شما: {otpCode}"
            });
        }
    }
}