using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SSO.Models;

namespace IdentityServer4.Plus.UserInteraction.Pages.Logout
{
    public class LogoutPage : PageModel
    {
        public string LogoutId { get; set; }
        public string PostLogoutRedirectUrl { get; set; }
        public string SignOutIFrameUrl { get; set; }
        public void OnGet()
        {
            
        }

        // public Task<IActionResult> OnPost()
        // {
        //     var context = await _identityServerInteractionService.GetLogoutContextAsync(logoutModel?.LogoutId);
        //     if (context == null)
        //     {
        //         _logger.Verbose("Invalid logout Id {@LogoutId}", logoutModel?.LogoutId);
        //         return BadRequest();
        //     }
        //
        //     await HttpContext.SignOutAsync(Constants.DefaultAuthenticationSchemeName);
        //     return Ok(new LogoutResult()
        //     {
        //         SignOutIFrameUrl = context.SignOutIFrameUrl,
        //         PostLogoutRedirectUrl = context.PostLogoutRedirectUri ?? configuration["Settings:DefaultPostLogoutUrl"],
        //     });
        // }
    }
}