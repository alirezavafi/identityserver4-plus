using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using CoreLib.Services.Otp;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Serilog;
using Serilog.Context;
using SSO.Controllers;
using SSO.Identity;

namespace IdentityServer4.Plus.Modules.Authentication.Pages
{
    public class LoginOtp : PageModel
    {
        private readonly ApplicationUserManager _userManager;
        private readonly ILogger _logger;
        private readonly IOtpService _otpService;
        private readonly IIdentityServerInteractionService _identityServerInteractionService;
        private readonly ISmsService _smsService;

        public LoginOtp(ApplicationUserManager userManager, ILogger logger, IOtpService otpService
            , IIdentityServerInteractionService identityServerInteractionService, ISmsService smsService)
        {
            _userManager = userManager;
            _logger = logger;
            _otpService = otpService;
            _identityServerInteractionService = identityServerInteractionService;
            _smsService = smsService;
        }

        
        [Required]
        [StringLength(30)]
        [BindProperty(SupportsGet = true)]
        public string MobileNumber { get; set; }
        [Required]
        [StringLength(2048)]
        [BindProperty(SupportsGet = true)]
        public string ReturnUrl { get; set; }
        
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
            var context = await _identityServerInteractionService.GetAuthorizationContextAsync(ReturnUrl);
            if (context == null)
            {
                _logger.Verbose("ReturnUrl invalid, cannot find authorization context", ModelState.Values);
                return BadRequest();
            }
            
            using var logContext = LogContext.PushProperty("MobileNumber", MobileNumber);
            var existingUsers = await _userManager.FindAllByPhoneNumberAsync(MobileNumber);
            string otpCode;
            if (!existingUsers.Any())
            {
                _logger.Information("User not exists, trying to authenticate for registration", ModelState.Values);
                otpCode = _otpService.GenerateOtp(MobileNumber);
            }
            else
            {
                _logger.Information("User already exists, generating user otp", ModelState.Values);
                otpCode = await _userManager.GenerateChangePhoneNumberTokenAsync(existingUsers[0], MobileNumber);
            }
            
            await this.SendOtpCode(MobileNumber, otpCode);
            return RedirectToPage("VerifyOtp");
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