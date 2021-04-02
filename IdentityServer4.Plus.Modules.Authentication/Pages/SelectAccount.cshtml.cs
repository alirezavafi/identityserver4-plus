using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using System.Threading.Tasks;
using CoreLib.Services.Otp;
using IdentityServer4.Events;
using IdentityServer4.Plus.Modules.Authentication;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using Serilog;
using Serilog.Context;
using SSO.Identity;
using SSO.Models;

namespace IdentityServer4.Plus.UserInteraction.Pages.AccountSelection
{
    public class SelectAccountPage : PageModel
    {
        private readonly IIdentityServerInteractionService _interactionService;
        private readonly ILogger _logger;
        private readonly ApplicationUserManager _userManager;
        private readonly ApplicationSigninManager _signinManager;
        private readonly IEventService _eventService;
        private readonly IOptions<IdentityServerPlusOptions> _options;

        [Required] [StringLength(2048)] [BindProperty] public string ReturnUrl { get; set; }

        [Required] [StringLength(30)] [BindProperty] public string SelectedUsername { get; set; }

        public IEnumerable<ApplicationUser> AvailableUsers { get; set; }

        public SelectAccountPage(
            IIdentityServerInteractionService interactionService,
            ILogger logger,
            ApplicationUserManager userManager,
            ApplicationSigninManager signinManager,
            IEventService eventService,
            IOptions<IdentityServerPlusOptions> options
        )
        {
            _interactionService = interactionService;
            _logger = logger;
            _userManager = userManager;
            _signinManager = signinManager;
            _eventService = eventService;
            _options = options;
        }

        public async Task<IActionResult> OnGet()
        {
            _logger.Verbose("Trying to authenticate user partially");
            var authResult = await HttpContext.AuthenticateAsync(Core.Constants.PartialAuthenticationSchemeName);
            var authUser = authResult.Principal;
            if (!authResult.Succeeded ||
                authResult.Ticket.AuthenticationScheme != Core.Constants.PartialAuthenticationSchemeName)
            {
                _logger.Information("Cannot authenticate user {@Result}", authResult);
                return RedirectToPage("LoginOtp");
            }

            return Page();
        }

        public async Task<IActionResult> OnPost()
        {
            _logger.Verbose("Trying to authenticate user partially");
            var authResult = await HttpContext.AuthenticateAsync(Core.Constants.PartialAuthenticationSchemeName);
            var authUser = authResult.Principal;
            if (!authResult.Succeeded ||
                authResult.Ticket.AuthenticationScheme != Core.Constants.PartialAuthenticationSchemeName)
            {
                _logger.Information("Cannot authenticate user {@Result}", authResult);
                return Unauthorized();
            }

            var mobileNumber = authUser.FindFirstValue(Core.Constants.Claims.MobileNumber);
            using var logContext2 = LogContext.PushProperty("MobileNumber", mobileNumber);

            var context = await _interactionService.GetAuthorizationContextAsync(ReturnUrl);
            if (context == null)
            {
                _logger.Verbose("ReturnUrl invalid, cannot find authorization context", ModelState.Values);
                return BadRequest();
            }

            if (!ModelState.IsValid)
            {
                _logger.Verbose("Invalid {@Input}", ModelState.Values);
                return BadRequest(ModelState);
            }

            var existingUser = await _userManager.FindByNameAsync(authUser.Identity.Name);
            if (existingUser == null)
            {
                _logger.Warning("Invalid user, cannot find user");
                return BadRequest();
            }

            if (existingUser.MobileNumber != mobileNumber)
            {
                _logger.Warning("Selected {@User} does not belong to mobile number", existingUser);
                return BadRequest();
            }

            var isUserLockedOut = await _userManager.IsLockedOutAsync(existingUser);
            if (isUserLockedOut)
            {
                _logger.Information("{@User} locked-out prior to anomaly", existingUser);
                await _eventService.RaiseAsync(new UserLoginFailureEvent(mobileNumber, "account locked-out",
                    clientId: context?.Client.ClientId));
                await _userManager.AccessFailedAsync(existingUser);
                return Unauthorized();
            }

            var isUserLogonEnabled = await _userManager.IsUserLogonEnabledAsync(existingUser);
            if (!isUserLogonEnabled)
            {
                _logger.Information("{@User} logon is not enabled", existingUser);
                await _eventService.RaiseAsync(new UserLoginFailureEvent(mobileNumber, "account logon not enabled",
                    clientId: context?.Client.ClientId));
                await _userManager.AccessFailedAsync(existingUser);
                return Unauthorized();
            }

            await _signinManager.SignIn(existingUser, context.Client.ClientId);
            return Redirect(ReturnUrl);
        }
    }
}