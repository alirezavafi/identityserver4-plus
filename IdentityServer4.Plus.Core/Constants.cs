namespace IdentityServer4.Plus.Core
{
    public static class Constants
    {
        public static class Claims
        {
            public const string MobileNumber = "phone";
            public const string VisitorCode = "visitorCode";
            public const string Email = "email";
            public const string MobileNumberConfirmed = "phone_confirmed";
            public const string EmailConfirmed = "email_confirmed";
            public const string NationalCode = "national_code";
            public const string MembershipStatus = "membership_status";
        }

        public const string PartialAuthenticationSchemeName = "partial-auth";
        public const string DefaultAuthenticationSchemeName = "local-auth";
    }
}