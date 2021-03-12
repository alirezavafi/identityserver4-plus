using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityServer4.Events;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Serilog.Context;
using SSO.Models;

namespace IdentityServer4.Plus.UserInteraction.Pages.AccountSelection
{
    public class SelectAccountPage : PageModel
    {
        [Required]
        [StringLength(2048)]
        public string ReturnUrl { get; set; }
        [StringLength(30)]
        public string Username { get; set; }
        
        public void OnGet()
        {
        //     _logger.Verbose("Trying to authenticate user partially");
        //     var authResult = await HttpContext.AuthenticateAsync(Constants.PartialAuthenticationSchemeName);
        //     var authUser = authResult.Principal;
        //     if (!authResult.Succeeded ||
        //         authResult.Ticket.AuthenticationScheme != Constants.PartialAuthenticationSchemeName)
        //     {
        //         _logger.Information("Cannot authenticate user {@Result}", authResult);
        //         return Unauthorized();
        //     }
        //
        //     var mobileNumber = authUser.FindFirstValue(Constants.Claims.MobileNumber);
        //     using var logContext2 = LogContext.PushProperty("MobileNumber", mobileNumber);
        //
        //     var context = await _identityServerInteractionService.GetAuthorizationContextAsync(model.ReturnUrl);
        //     if (context == null)
        //     {
        //         _logger.Verbose("ReturnUrl invalid, cannot find authorization context", ModelState.Values);
        //         return BadRequest();
        //     }
        //
        //     if (!ModelState.IsValid)
        //     {
        //         _logger.Verbose("Invalid {@Input}", ModelState.Values);
        //         return BadRequest(ModelState);
        //     }
        //
        //     var existingUser = await _userManager.FindByNameAsync(model.Username);
        //     if (existingUser == null)
        //     {
        //         _logger.Warning("Invalid user, cannot find user");
        //         return BadRequest();
        //     }
        //
        //     if (existingUser.MobileNumber != mobileNumber)
        //     {
        //         _logger.Warning("Selected {@User} does not belong to mobile number", existingUser);
        //         return BadRequest();
        //     }
        //
        //     var isUserLockedOut = await _userManager.IsLockedOutAsync(existingUser);
        //     if (isUserLockedOut)
        //     {
        //         _logger.Information("{@User} locked-out prior to anomaly", existingUser);
        //         await _events.RaiseAsync(new UserLoginFailureEvent(mobileNumber, "account locked-out",
        //             clientId: context?.Client.ClientId));
        //         await _userManager.AccessFailedAsync(existingUser);
        //         return Unauthorized();
        //     }
        //
        //     var isUserLogonEnabled = await _userManager.IsUserLogonEnabledAsync(existingUser);
        //     if (!isUserLogonEnabled)
        //     {
        //         _logger.Information("{@User} logon is not enabled", existingUser);
        //         await _events.RaiseAsync(new UserLoginFailureEvent(mobileNumber, "account logon not enabled",
        //             clientId: context?.Client.ClientId));
        //         await _userManager.AccessFailedAsync(existingUser);
        //         return Unauthorized();
        //     }
        //
        //     await _signinManager.SignIn(existingUser, context.Client.ClientId);
        //     return Ok(new LoginResult()
        //     {
        //         IsLoggedIn = true,
        //     });
        }
    }
}