﻿using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.ServiceModel;
using System.Threading;
using System.Threading.Tasks;

namespace SSO.Identity
{
    public class ApplicationUserManager : UserManager<ApplicationUser>
    {
        private readonly IApplicationUserStore store;

        public ApplicationUserManager(IApplicationUserStore store, IOptions<IdentityOptions> optionsAccessor, IPasswordHasher<ApplicationUser> passwordHasher, IEnumerable<IUserValidator<ApplicationUser>> userValidators, IEnumerable<IPasswordValidator<ApplicationUser>> passwordValidators, ILookupNormalizer keyNormalizer, IdentityErrorDescriber errors, IServiceProvider services, ILogger<UserManager<ApplicationUser>> logger) : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
        {
            this.store = store;
        }

        public Task SetSuccessfulLogin(ApplicationUser user)
        {
            user.LastSuccessfullLogin = DateTime.Now.ToUniversalTime();
            return store.UpdateAsync(user, CancellationToken.None);
        }

        public Task<bool> IsUserLogonEnabledAsync(ApplicationUser user)
        {
            return Task.FromResult(user.LogonEnabled);
        }

		public Task<List<ApplicationUser>> FindAllByPhoneNumberAsync(string mobile, CancellationToken cancellationToken = default)
        {
			return store.FindByPhoneNumberAsync(mobile, cancellationToken);
        }
        public async Task<ApplicationUser> FindFirstByPhoneNumberAsync(string mobile, CancellationToken cancellationToken = default)
        {
            return (await store.FindByPhoneNumberAsync(mobile, cancellationToken)).FirstOrDefault();
        }
    }
}