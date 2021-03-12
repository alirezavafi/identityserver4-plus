using IdentityModel;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace SSO.Identity
{
    public abstract class ApplicationUserStoreBase : IApplicationUserStore
    {
		#region IUserPasswordStore
		public Task SetPasswordHashAsync(ApplicationUser user, string passwordHash, CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			user.PasswordHash = passwordHash;
			return Task.FromResult(0);
		}

		public Task<string> GetPasswordHashAsync(ApplicationUser user, CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			return Task.FromResult(user.PasswordHash);
		}

		public Task<bool> HasPasswordAsync(ApplicationUser user, CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			return Task.FromResult(!string.IsNullOrWhiteSpace(user.PasswordHash));
		}

		#endregion

		#region IUserEmailStore

		public Task SetEmailAsync(ApplicationUser user, string email, CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			user.Email = email;
			return Task.FromResult(0);
		}

		public Task<string> GetEmailAsync(ApplicationUser user, CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			return Task.FromResult(user.Email);
		}

		public Task<bool> GetEmailConfirmedAsync(ApplicationUser user, CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			return Task.FromResult(user.EmailConfirmed);
		}

		public Task SetEmailConfirmedAsync(ApplicationUser user, bool confirmed, CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			user.EmailConfirmed = confirmed;
			return Task.FromResult(0);
		}

		public Task<string> GetNormalizedEmailAsync(ApplicationUser user, CancellationToken cancellationToken)
		{
			ThrowIfDisposed();

			return Task.FromResult(user.Email?.ToUpper());
		}

		public Task SetNormalizedEmailAsync(ApplicationUser user, string normalizedEmail, CancellationToken cancellationToken)
		{
			ThrowIfDisposed();

			user.Email = normalizedEmail?.ToUpper();
			return Task.FromResult(0);
		}

		#endregion

		#region IUserPhoneNumberStore

		public Task<string> GetPhoneNumberAsync(ApplicationUser user, CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			return Task.FromResult(user.MobileNumber);
		}

		public Task<bool> GetPhoneNumberConfirmedAsync(ApplicationUser user, CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			return Task.FromResult(user.MobileNumberConfirmed);
		}

		public Task SetPhoneNumberAsync(ApplicationUser user, string phoneNumber, CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			user.MobileNumber = phoneNumber;
			return Task.FromResult(0);
		}

		public Task SetPhoneNumberConfirmedAsync(ApplicationUser user, bool confirmed, CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			user.MobileNumberConfirmed = confirmed;
			return Task.FromResult(0);
		}

		#endregion

		#region IUserSecurityStampStore

		public Task<string> GetSecurityStampAsync(ApplicationUser user, CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			return Task.FromResult(user.SecurityStamp);
		}

		public Task SetSecurityStampAsync(ApplicationUser user, string stamp, CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			user.SecurityStamp = stamp;
			return Task.FromResult(0);
		}

		#endregion

		#region IUserLockoutStore

		public Task<int> GetAccessFailedCountAsync(ApplicationUser user, CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			return Task.FromResult(user.AccessFailedCount);
		}

		public Task<bool> GetLockoutEnabledAsync(ApplicationUser user, CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			return Task.FromResult(user.LockoutEnabled);
		}

		public Task<DateTimeOffset?> GetLockoutEndDateAsync(ApplicationUser user, CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			return Task.FromResult(user.LockoutEndDate);
		}

		public Task<int> IncrementAccessFailedCountAsync(ApplicationUser user, CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			++user.AccessFailedCount;
			return Task.FromResult(user.AccessFailedCount);
		}

		public Task ResetAccessFailedCountAsync(ApplicationUser user, CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			user.AccessFailedCount = 0;
			return Task.FromResult(0);
		}

		public Task SetLockoutEnabledAsync(ApplicationUser user, bool enabled, CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			user.LockoutEnabled = enabled;
			return Task.FromResult(0);
		}

		public Task SetLockoutEndDateAsync(ApplicationUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			user.LockoutEndDate = lockoutEnd;
			return Task.FromResult(0);
		}

		#endregion

		public Task<string> GetNormalizedUserNameAsync(ApplicationUser user, CancellationToken cancellationToken = default)
        {
			ThrowIfDisposed();

			return Task.FromResult(user.UserName?.ToUpper());
		}

        public Task<string> GetUserIdAsync(ApplicationUser user, CancellationToken cancellationToken = default)
        {
			ThrowIfDisposed();

			return Task.FromResult(user.Id.ToString());
		}

        public Task<string> GetUserNameAsync(ApplicationUser user, CancellationToken cancellationToken = default)
        {
			ThrowIfDisposed();

			return Task.FromResult(user.UserName);
		}

        public Task SetNormalizedUserNameAsync(ApplicationUser user, string normalizedName, CancellationToken cancellationToken = default)
        {
			ThrowIfDisposed();

			user.NormalizedUserName = normalizedName?.ToUpper();
			return Task.FromResult(0);
		}

        public Task SetUserNameAsync(ApplicationUser user, string userName, CancellationToken cancellationToken = default)
        {
			ThrowIfDisposed();

			user.UserName = userName?.ToUpper();
			return Task.FromResult(0);
		}

		public abstract Task<IdentityResult> CreateAsync(ApplicationUser user, CancellationToken cancellationToken = default);
		public abstract Task<IdentityResult> DeleteAsync(ApplicationUser user, CancellationToken cancellationToken = default);
		public abstract Task<IdentityResult> UpdateAsync(ApplicationUser user, CancellationToken cancellationToken);
		public abstract Task<ApplicationUser> FindByIdAsync(string userId, CancellationToken cancellationToken = default);
		public abstract Task<ApplicationUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken = default);
		public abstract Task<ApplicationUser> FindByEmailAsync(string email, CancellationToken cancellationToken = default);
		public abstract Task<List<ApplicationUser>> FindByPhoneNumberAsync(string mobile, CancellationToken cancellationToken = default);
		public abstract Task<List<ApplicationUser>> FindByAnyIdentifierAsync(string identifier, CancellationToken cancellationToken = default);
		

		#region IDisposable

		private bool _disposed;

		public void Dispose()
		{
			Dispose(true);
			GC.SuppressFinalize(this);
		}

		protected virtual void Dispose(bool disposing)
		{
			if (_disposed) return;

			_disposed = true;
		}

		protected void ThrowIfDisposed()
		{
			if (_disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
		}

		#endregion
	}
}
