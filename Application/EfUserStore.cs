using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace SSO.Identity.Stores.EntityFramework
{
    public class EfUserStore : ApplicationUserStoreBase
    {
        private readonly ApplicationIdentityDbContext dbContext;

        public EfUserStore(ApplicationIdentityDbContext dbContext)
        {
            this.dbContext = dbContext;
        }

        public override async Task<IdentityResult> CreateAsync(ApplicationUser user, CancellationToken cancellationToken = default)
        {
            dbContext.Users.Add(user);
            await dbContext.SaveChangesAsync(cancellationToken);
            return IdentityResult.Success;
        }

        public override async Task<IdentityResult> DeleteAsync(ApplicationUser user, CancellationToken cancellationToken = default)
        {
            dbContext.Users.Remove(user);
            await dbContext.SaveChangesAsync(cancellationToken);
            return IdentityResult.Success;
        }

        public override Task<ApplicationUser> FindByEmailAsync(string email, CancellationToken cancellationToken = default)
        {
            return dbContext.Users.FirstOrDefaultAsync(x => x.Email == email);
        }

        public override Task<ApplicationUser> FindByIdAsync(string userId, CancellationToken cancellationToken = default)
        {
            var id = Guid.Parse(userId);
            return dbContext.Users.SingleOrDefaultAsync(x => x.Id == id);
        }

        public override Task<ApplicationUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken = default)
        {
            return dbContext.Users.FirstOrDefaultAsync(x => x.NormalizedUserName == normalizedUserName);
        }

        public override Task<List<ApplicationUser>> FindByPhoneNumberAsync(string mobile, CancellationToken cancellationToken = default)
        {
            return dbContext.Users.Where(x => x.MobileNumber == mobile).ToListAsync();

        }

        public override async Task<IdentityResult> UpdateAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            dbContext.Users.Update(user);
            await dbContext.SaveChangesAsync(cancellationToken);
            return IdentityResult.Success;
        }
    }
}
