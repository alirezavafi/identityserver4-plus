using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Persian.Plus.Core.Extensions;
using Serilog;
using SSO.Controllers;
using SSO.Identity;

namespace IdentityServer4.Plus.UserInteraction.Pages
{
    public class UsernamePage : PageModel
    {
        private readonly ApplicationUserManager _userManager;
        private readonly ISmsService _smsService;
        private readonly ILogger _logger;

        public UsernamePage(ApplicationUserManager userManager, ISmsService smsService,
            ILogger logger)
        {
            _userManager = userManager;
            _smsService = smsService;
            _logger = logger;
        }
        
        public string Username { get; set; }

        public IActionResult OnGet()
        {
            return Page();
        }

        public async Task<IActionResult> OnPost()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            if (Username.IsIranianMobileNumber())
            {
                var existingAccount = await _userManager.FindFirstByPhoneNumberAsync(Username);
                if (existingAccount != null)
                {
                    var otpCode = await _userManager.GenerateChangePhoneNumberTokenAsync(existingAccount, Username);
                    await SendOtpCode(Username, otpCode);
                    return RedirectToPage("LoginByOtp");
                }

                return Page();
            }
            else if (IsValidEmail(Username))
            {
                return RedirectToPage("LoginByPassword");
            }
            else
            {
                return RedirectToPage("LoginByPassword");
            }

            return Page();  
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

        
        bool IsValidEmail(string email)
        {
            try {
                var addr = new System.Net.Mail.MailAddress(email);
                return addr.Address == email;
            }
            catch {
                return false;
            }
        }
    }
}