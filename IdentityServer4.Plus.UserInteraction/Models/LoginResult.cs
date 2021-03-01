using System.Collections.Generic;

namespace SSO.Models
{
    public class LoginResult
    {
        public bool MustRegister { get; set; }
        public bool IsLoggedIn { get; set; }
        public bool MustSelectUser { get; set; }
        public IEnumerable<AvailableUser> AvailableUsers { get; set; } = new List<AvailableUser>();
    }

    public class AvailableUser
    {
        public string Username { get; set; }
        public string FullName { get; set; }
    }
}
