using System;
using System.Security.Principal;

namespace SSO.Identity
{
    public class ApplicationUser : IIdentity
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string UserName { get; set; }
        public string Email { get; set; }
        public bool EmailConfirmed { get; set; }
        public string MobileNumber { get; set; }
        public bool MobileNumberConfirmed { get; set; }
        public string PasswordHash { get; set; }
        public string SecurityStamp { get; set; } = Guid.NewGuid().ToString();
        public string NormalizedUserName { get; set; }
        public string AuthenticationType { get; set; }
        public bool IsAuthenticated { get; set; }
        public string NationalCode { get; set; }
        public DateTimeOffset? LockoutEndDate { get; set; } = new DateTime(2000, 1, 1);
        public DateTimeOffset? LastSuccessfullLogin { get; set; }
        public bool LockoutEnabled { get; set; } = true;
        public bool LogonEnabled { get; set; } = true;
        public int AccessFailedCount { get; set; }
		public string Name => UserName;
        public string FirstName { get; set; }
        public string LastName { get; set; }
    }
}
