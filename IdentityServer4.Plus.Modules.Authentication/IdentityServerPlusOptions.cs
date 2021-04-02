using System;
using Microsoft.EntityFrameworkCore;

namespace IdentityServer4.Plus.Modules.Authentication
{
    public class IdentityServerPlusOptions
    {
        public int SsoLifeTimeInMinutes { get; set; } = 120;
        public bool SsoIsSlidingExpiration { get; set; } = false;
        public Action<DbContextOptionsBuilder> DbContextConfiguration { get; set; }
        public string TokenSigningCertificatePath { get; set; }
        public string TokenSigningCertificationPassword { get; set; }
        public bool AllowSignup { get; set; }
    }
}