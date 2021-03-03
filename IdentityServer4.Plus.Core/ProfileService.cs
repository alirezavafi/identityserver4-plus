using IdentityServer4.Models;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace SSO.Identity
{
    public class ProfileService : IProfileService
    {
        protected ApplicationUserManager _userManager;

        public ProfileService(ApplicationUserManager userManager)
        {
            _userManager = userManager;
        }

        public Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            foreach (var requestedClaimType in context.RequestedClaimTypes)
            {
                var matchedClaims = context.Subject.FindAll(x => x.Type == requestedClaimType).ToList();
                context.IssuedClaims.AddRange(matchedClaims);
            }

            return Task.CompletedTask;
        }

        public async Task IsActiveAsync(IsActiveContext context)
        {
            var user = await _userManager.GetUserAsync(context.Subject);
            context.IsActive = (user != null) && user.LogonEnabled;
        }
    }
}
