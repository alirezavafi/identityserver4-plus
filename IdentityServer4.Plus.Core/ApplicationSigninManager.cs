using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityServer4;
using IdentityServer4.Events;
using IdentityServer4.Models;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Serilog;

namespace SSO.Identity
{
    public class ApplicationSigninManager
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ApplicationUserManager _userManager;
        private readonly ILogger _logger;
        private readonly IEventService _eventService;

        public ApplicationSigninManager(IHttpContextAccessor httpContextAccessor, ApplicationUserManager userManager, ILogger logger, IEventService eventService)
        {
            _httpContextAccessor = httpContextAccessor;
            _userManager = userManager;
            _logger = logger;
            _eventService = eventService;
        }
        
        public async Task SignInPartial(string mobileNumber)
        {
            var claims = new List<Claim>()
            {
                new Claim(Constants.Claims.MobileNumber, mobileNumber),
            };
            var claimsIdentity = new ClaimsIdentity(claims, Constants.PartialAuthenticationSchemeName);
            var props = new AuthenticationProperties();
            await _httpContextAccessor.HttpContext.SignInAsync(
                scheme: Constants.PartialAuthenticationSchemeName,
                properties: props,
                principal: new ClaimsPrincipal(claimsIdentity));

            _logger.Information("User patially authenticated and must register to continue");
        }

        public async Task SignIn(ApplicationUser user, string clientId)
        {
            var authResult = await _httpContextAccessor.HttpContext.AuthenticateAsync(Constants.PartialAuthenticationSchemeName);
            var authUser = authResult.Principal;
            var visitorCode = string.Empty;
            if (authResult.Succeeded && authResult.Ticket.AuthenticationScheme == Constants.PartialAuthenticationSchemeName)
            {
                visitorCode = authUser.FindFirstValue(Constants.Claims.VisitorCode);
            }

            await this.SignOutPartial();
            await this.SignInInternal(user);
            await _eventService.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.UserIdentityNumber, user.UserName, clientId: clientId));
            _logger.Information("{@User} logged-in", user);
        }
        
        private Task SignOutPartial()
        {
            return _httpContextAccessor.HttpContext.SignOutAsync(Constants.PartialAuthenticationSchemeName);
        }

        private async Task SignInInternal(ApplicationUser user)
        {
            var props = new AuthenticationProperties();
            var claims = new List<Claim>() {
                new Claim(Constants.Claims.MobileNumber, user.MobileNumber),
                new Claim(Constants.Claims.NationalCode, user.UserIdentityNumber),
                new Claim("given_name", user.FirstName),
                new Claim("family_name", user.LastName),
            };
            var isuser = new IdentityServerUser(user.Id.ToString())
            {
                DisplayName = $"{user.FirstName} {user.LastName}",
                AdditionalClaims = claims
            };
            
            await _userManager.SetSuccessfulLogin(user);
            await _userManager.ResetAccessFailedCountAsync(user);
            var userPrincipal = isuser.CreatePrincipal();
            await _httpContextAccessor.HttpContext.SignInAsync(Constants.DefaultAuthenticationSchemeName, userPrincipal, props);
        }

    }
}