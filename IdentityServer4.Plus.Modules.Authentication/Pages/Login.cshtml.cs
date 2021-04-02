using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using CoreLib.Services.Otp;
using IdentityServer4.Events;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Serilog;
using Serilog.Context;
using SSO.Controllers;
using SSO.Identity;

namespace IdentityServer4.Plus.Modules.Authentication.Pages
{
    public class Login : PageModel
    {
        private readonly ApplicationUserManager _userManager;
        private readonly ILogger _logger;
        private readonly IOtpService _otpService;
        private readonly IIdentityServerInteractionService _interactionService;
        private readonly IEventService _eventService;
        private readonly ApplicationSigninManager _signinManager;

        public Login(
            ApplicationUserManager userManager,
            ILogger logger,
            IOtpService otpService,
            IIdentityServerInteractionService interactionService,
            IEventService eventService,
            ApplicationSigninManager signinManager)
        {
            _userManager = userManager;
            _logger = logger;
            _otpService = otpService;
            _interactionService = interactionService;
            _eventService = eventService;
            _signinManager = signinManager;
        }


        [Required]
        [StringLength(30)]
        [BindProperty]
        public string UserIdentifier { get; set; }

        [Required]
        [StringLength(30)]
        [BindProperty]
        public string Password { get; set; }

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
            using var logContext = LogContext.PushProperty("UserIdentifier", UserIdentifier);

            if (!ModelState.IsValid)
            {
                _logger.Verbose("Invalid {@Input}", ModelState.Values);
                return Page();
            }

            var context = await _interactionService.GetAuthorizationContextAsync(ReturnUrl);
            if (context == null)
            {
                _logger.Verbose("ReturnUrl invalid, cannot find authorization context", ModelState.Values);
                ModelState.AddModelError("Unauthorized", "Unauthorized");
                return Page();
            }

            var existingUser = (await _userManager.FindAllByAnyIdentifierAsync(UserIdentifier)).SingleOrDefault();
            string otpCode;
            if (existingUser == null)
            {
                _logger.Information("User not exists, trying to authenticate for registration", ModelState.Values);
                ModelState.AddModelError("Unauthorized", "Unauthorized");
                return Page();
            }

            using var l1 = LogContext.PushProperty("UserMobile", existingUser.MobileNumber);
            using var l2 = LogContext.PushProperty("UserEmail", existingUser.Email);
            using var l3 = LogContext.PushProperty("Username", existingUser.UserName);
            var isUserLockedOut = await _userManager.IsLockedOutAsync(existingUser);
            if (isUserLockedOut)
            {
                _logger.Information("{@User} locked-out prior to anomaly", existingUser);
                await _eventService.RaiseAsync(new UserLoginFailureEvent(existingUser.UserName, "account locked-out",
                    clientId: context?.Client.ClientId));
                await _userManager.AccessFailedAsync(existingUser);
                ModelState.AddModelError("Unauthorized", "Unauthorized");
                return Page();
            }

            var isUserLogonEnabled = await _userManager.IsUserLogonEnabledAsync(existingUser);
            if (!isUserLogonEnabled)
            {
                _logger.Information("{@User} logon is not enabled", existingUser);
                await _eventService.RaiseAsync(new UserLoginFailureEvent(existingUser.UserName,
                    "account logon not enabled", clientId: context?.Client.ClientId));
                await _userManager.AccessFailedAsync(existingUser);
                ModelState.AddModelError("Unauthorized", "Unauthorized");
                return Page();
            }

            var isValidPassword = await _userManager.CheckPasswordAsync(existingUser, Password);
            if (!isValidPassword)
            {
                _logger.Information("{@User} entered invalid password", existingUser);
                await _eventService.RaiseAsync(new UserLoginFailureEvent(existingUser.UserName, "invalid credentials",
                    clientId: context?.Client.ClientId));
                await _userManager.AccessFailedAsync(existingUser);
                ModelState.AddModelError("Unauthorized", "Unauthorized");
                return Page();
            }

            await _signinManager.SignIn(existingUser, context.Client.ClientId);
            return Redirect(ReturnUrl);
        }
    }
}