using Microsoft.AspNetCore.Identity;
using System.Threading;
using System.Threading.Tasks;

namespace SSO.Identity
{
    public class NullRoleStore : IRoleStore<ApplicationRole>
    {
        public Task<IdentityResult> CreateAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
			return Task.FromResult(IdentityResult.Success);
        }

        public Task<IdentityResult> DeleteAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
			return Task.FromResult(IdentityResult.Success);
		}

		public void Dispose()
        {
        }

        public Task<ApplicationRole> FindByIdAsync(string roleId, CancellationToken cancellationToken)
        {
			return Task.FromResult<ApplicationRole>(null);
        }

        public Task<ApplicationRole> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken)
        {
			return Task.FromResult<ApplicationRole>(null);
		}

		public Task<string> GetNormalizedRoleNameAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
			return Task.FromResult(role.NormalizedName);
        }

        public Task<string> GetRoleIdAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
			return Task.FromResult(role.Name?.ToUpper());
		}

		public Task<string> GetRoleNameAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
			return Task.FromResult(role.Name);
		}

		public Task SetNormalizedRoleNameAsync(ApplicationRole role, string normalizedName, CancellationToken cancellationToken)
        {
			role.NormalizedName = normalizedName.ToUpper();
			return Task.CompletedTask;
        }

        public Task SetRoleNameAsync(ApplicationRole role, string roleName, CancellationToken cancellationToken)
        {
			role.Name = roleName;
			return Task.CompletedTask;
		}

		public Task<IdentityResult> UpdateAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
			return Task.FromResult(IdentityResult.Success);
		}
	}
}
