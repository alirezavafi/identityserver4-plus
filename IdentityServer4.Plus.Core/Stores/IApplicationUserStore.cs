using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace SSO.Identity
{
    public interface IApplicationUserStore : IUserStore<ApplicationUser>,
						 IUserPasswordStore<ApplicationUser>,
						 IUserSecurityStampStore<ApplicationUser>,
						 IUserLockoutStore<ApplicationUser>,
						 IUserEmailStore<ApplicationUser>,
						 IUserPhoneNumberStore<ApplicationUser>
	{
		Task<List<ApplicationUser>> FindByPhoneNumberAsync(string mobile, CancellationToken cancellationToken = default);
	}
}
