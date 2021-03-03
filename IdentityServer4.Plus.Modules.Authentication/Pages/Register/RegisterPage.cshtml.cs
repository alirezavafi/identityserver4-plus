using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Serilog.Context;
using SSO.Identity;
using SSO.Models;

namespace IdentityServer4.Plus.UserInteraction.Pages.Register
{
    public class RegisterPage : PageModel
    {
        public void OnGet()
        {
            
        }

        public async Task<IActionResult> OnPost()
        {
              using var logContext = LogContext.PushProperty("NationalCode", model.NationalCode);

            var context = await _identityServerInteractionService.GetAuthorizationContextAsync(model.ReturnUrl);
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

            _logger.Verbose("Trying to authenticate user partially");
            var authResult = await HttpContext.AuthenticateAsync(Constants.PartialAuthenticationSchemeName);
            var authUser = authResult.Principal;
            if (!authResult.Succeeded || authResult.Ticket.AuthenticationScheme != Constants.PartialAuthenticationSchemeName)
            {
                _logger.Information("Cannot authenticate user {@Result}", authResult);
                return Unauthorized();
            }

            var mobileNumber = authUser.FindFirstValue(Constants.Claims.MobileNumber);
            using var logContext2 = LogContext.PushProperty("MobileNumber", mobileNumber);

            var visitorCode = authUser.FindFirstValue(Constants.Claims.VisitorCode);
            var userName = model.NationalCode;
            var existingUser = await _userManager.FindByNameAsync(userName);
            if (existingUser != null)
            {
                _logger.Warning("{@User} already exists and cannot register", existingUser);
                return Conflict();
            }

            var user = new ApplicationUser
            {
                UserName = userName,
                NormalizedUserName = userName,
                UserIdentityNumber = model.NationalCode,
                FirstName = model.FirstName,
                LastName = model.LastName,
                MobileNumber = mobileNumber,
                MobileNumberConfirmed = true,
            };
            var result = await _userManager.CreateAsync(user);
            if (result.Succeeded)
            {
                _logger.Information("Created new {@User}", user);
                await _signinManager.SignIn(user, context.Client.ClientId);
                return Ok(new LoginResult()
                {
                    IsLoggedIn = true,
                });
            }
            else
            {
                _logger.Warning("{@User} failed to create with {@Result}", user, result);
                var duplicateError = new IdentityErrorDescriber().DuplicateUserName(user.UserName);
                var duplicateUser = await _userManager.FindByNameAsync(user.UserName);
                if (result.Errors.Any<IdentityError>(x => x.Code == duplicateError.Code))
                {
                    return Conflict();
                }

                return BadRequest();
            }
        }
    }
}