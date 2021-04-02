using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using CoreLib.Services.Otp;
using IdentityServer4.Events;
using IdentityServer4.Plus.Modules.Authentication;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using Serilog;
using Serilog.Context;
using SSO;
using SSO.Identity;
using SSO.Models;

namespace IdentityServer4.Plus.UserInteraction
{
    public class VerifyOtpPage : PageModel
    {
        private readonly IIdentityServerInteractionService _interactionService;
        private readonly ILogger _logger;
        private readonly ApplicationUserManager _userManager;
        private readonly ApplicationSigninManager _signinManager;
        private readonly IEventService _eventService;
        private readonly IOtpService _otpService;
        private readonly IOptions<IdentityServerPlusOptions> _options;
        private string otpCode;

        [Required]
        public string MobileNumber
        {
            get;
            set;
        }
        [Required]
        [StringLength(10)]
        public string OtpCode { get => otpCode; set => otpCode = value.RemoveStartingZeroIfExists(); }
        [Required]
        [StringLength(2048)]
        public string ReturnUrl { get; set; }
        
        [StringLength(2048)]
        public string Referrer { get; set; }

        public VerifyOtpPage(
            IIdentityServerInteractionService interactionService, 
            ILogger logger,
            ApplicationUserManager userManager,
            ApplicationSigninManager signinManager,
            IEventService eventService,
            IOtpService otpService,
            IOptions<IdentityServerPlusOptions> options
            )
        {
            _interactionService = interactionService;
            _logger = logger;
            _userManager = userManager;
            _signinManager = signinManager;
            _eventService = eventService;
            _otpService = otpService;
            _options = options;
        }
        
        public async Task<IActionResult> OnPost()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }
            
            using var logContext = LogContext.PushProperty("MobileNumber", MobileNumber);
        
            var context = await _interactionService.GetAuthorizationContextAsync(ReturnUrl);
            if (context == null)
            {
                _logger.Verbose("ReturnUrl invalid, cannot find authorization context", ModelState.Values);
                ModelState.AddModelError("Unauthorized", "Invalid Url");
                return Page();
            }
        
            if (!ModelState.IsValid)
            {
                _logger.Verbose("Invalid {@Input}", ModelState.Values);
                return Page();
            }
        
            var existingUsers = await _userManager.FindAllByPhoneNumberAsync(MobileNumber);
        
            var existingUser = existingUsers.FirstOrDefault();
            if (existingUser == null)
            {
                if (_otpService.IsValidOtp(MobileNumber, OtpCode))
                {
                    await _signinManager.SignInPartial(MobileNumber);
                    if (_options.Value.AllowSignup)
                    {
                        return RedirectToPage("Register");
                    }
                    else
                    {
                        return RedirectToPage("UserNotFound");
                    }
                }
                else
                {
                    _logger.Information("Invalid otp for new user");
                    ModelState.AddModelError("Unauthorized", "Unauthorized");
                    return Page();
                }
            }
            else
            {
                var isUserLockedOut = await _userManager.IsLockedOutAsync(existingUser);
                if (isUserLockedOut)
                {
                    _logger.Information("{@User} locked-out prior to anomaly", existingUser);
                    await _eventService.RaiseAsync(new UserLoginFailureEvent(MobileNumber, "account locked-out", clientId: context?.Client.ClientId));
                    await _userManager.AccessFailedAsync(existingUser);
                    ModelState.AddModelError("Unauthorized", "Unauthorized");
                    return Page();
                }
                var isUserLogonEnabled = await _userManager.IsUserLogonEnabledAsync(existingUser);
                if (!isUserLogonEnabled)
                {
                    _logger.Information("{@User} logon is not enabled", existingUser);
                    await _eventService.RaiseAsync(new UserLoginFailureEvent(MobileNumber, "account logon not enabled", clientId: context?.Client.ClientId));
                    await _userManager.AccessFailedAsync(existingUser);
                    ModelState.AddModelError("Unauthorized", "Unauthorized");
                    return Page();
                }
        
                var isValidOtp = await _userManager.VerifyChangePhoneNumberTokenAsync(existingUser, OtpCode, MobileNumber);
                if (isValidOtp)
                {
                    await _signinManager.SignInPartial(MobileNumber);
                    return RedirectToPage("SelectAccount");
                    // return Ok(new LoginResult()
                    // {
                    //     MustSelectUser = true,
                    //     AvailableUsers = existingUsers.Select(x => new AvailableUser()
                    //     {
                    //         FullName = $"{x.FirstName} {x.LastName}",
                    //         Username = x.UserName
                    //     }).ToList(),
                    // });
                }
                else
                {
                    _logger.Information("Invalid otp for user {@User}", existingUser);
                    await _eventService.RaiseAsync(new UserLoginFailureEvent(MobileNumber, "invalid otp", clientId: context?.Client.ClientId));
                    await _userManager.AccessFailedAsync(existingUser);
                    ModelState.AddModelError("Unauthorized", "Unauthorized");
                    return Page();
                }
            }
        }
        
        private string MaskMobileNumber(string mobile)
        {
            if (string.IsNullOrWhiteSpace(mobile) || mobile.Length < 9)
            {
                return string.Empty;
            }

            return mobile.Remove(4, 3).Insert(4, "***");
        }
    }
}