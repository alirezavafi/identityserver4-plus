using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using IdentityServer4.Events;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Persian.Plus.Core.DataAnnotations;
using Persian.Plus.Core.Extensions;
using Serilog.Context;
using SSO;
using SSO.Models;

namespace IdentityServer4.Plus.UserInteraction
{
    public class LoginByOtpPage : PageModel
    {
        private string otpCode;
        private string mobileNumber;

        [Required]
        [IranianMobileNumber]
        public string MobileNumber { get => mobileNumber; set => mobileNumber = value.ToEnglishNumbers(); }
        [Required]
        [StringLength(10)]
        public string OtpCode { get => otpCode; set => otpCode = value.ToEnglishNumbers().RemoveStartingZeroIfExists(); }
        [Required]
        [StringLength(2048)]
        public string ReturnUrl { get; set; }
        
        [StringLength(2048)]
        public string Referrer { get; set; }
        public void OnGet()
        {
            
        }

        // public async Task<IActionResult> OnPost()
        // {
        //     if (!ModelState.IsValid)
        //     {
        //         return Page();
        //     }
        //     
        //     using var logContext = LogContext.PushProperty("MobileNumber", byOtpModel.MobileNumber);
        //
        //     var context = await _identityServerInteractionService.GetAuthorizationContextAsync(byOtpModel.ReturnUrl);
        //     if (context == null)
        //     {
        //         _logger.Verbose("ReturnUrl invalid, cannot find authorization context", ModelState.Values);
        //         return BadRequest();
        //     }
        //
        //     if (!ModelState.IsValid)
        //     {
        //         _logger.Verbose("Invalid {@Input}", ModelState.Values);
        //         return BadRequest(ModelState);
        //     }
        //
        //     var existingUsers = await _userManager.FindAllByPhoneNumberAsync(byOtpModel.MobileNumber);
        //
        //     var existingUser = existingUsers.FirstOrDefault();
        //     if (existingUser == null)
        //     {
        //         if (_otp.IsValidOtp(byOtpModel.MobileNumber, byOtpModel.OtpCode))
        //         {
        //             await _signinManager.SignInPartial(byOtpModel.MobileNumber);
        //             return Ok(new LoginResult() {MustRegister = true});
        //         }
        //         else
        //         {
        //             _logger.Information("Invalid otp for new user");
        //             return Unauthorized();
        //         }
        //     }
        //     else
        //     {
        //         var isUserLockedOut = await _userManager.IsLockedOutAsync(existingUser);
        //         if (isUserLockedOut)
        //         {
        //             _logger.Information("{@User} locked-out prior to anomaly", existingUser);
        //             await _events.RaiseAsync(new UserLoginFailureEvent(byOtpModel.MobileNumber, "account locked-out", clientId: context?.Client.ClientId));
        //             await _userManager.AccessFailedAsync(existingUser);
        //             return Unauthorized();
        //         }
        //         var isUserLogonEnabled = await _userManager.IsUserLogonEnabledAsync(existingUser);
        //         if (!isUserLogonEnabled)
        //         {
        //             _logger.Information("{@User} logon is not enabled", existingUser);
        //             await _events.RaiseAsync(new UserLoginFailureEvent(byOtpModel.MobileNumber, "account logon not enabled", clientId: context?.Client.ClientId));
        //             await _userManager.AccessFailedAsync(existingUser);
        //             return Unauthorized();
        //         }
        //
        //         var isValidOtp = await _userManager.VerifyChangePhoneNumberTokenAsync(existingUser, byOtpModel.OtpCode, byOtpModel.MobileNumber);
        //         if (isValidOtp)
        //         {
        //             await _signinManager.SignInPartial(byOtpModel.MobileNumber);
        //             return Ok(new LoginResult()
        //             {
        //                 MustSelectUser = true,
        //                 AvailableUsers = existingUsers.Select(x => new AvailableUser()
        //                 {
        //                     FullName = $"{x.FirstName} {x.LastName}",
        //                     Username = x.UserName
        //                 }).ToList(),
        //             });
        //         }
        //         else
        //         {
        //             _logger.Information("Invalid otp for user {@User}", existingUser);
        //             await _events.RaiseAsync(new UserLoginFailureEvent(byOtpModel.MobileNumber, "invalid otp", clientId: context?.Client.ClientId));
        //             await _userManager.AccessFailedAsync(existingUser);
        //             return Unauthorized();
        //         }
        //     }
        // }
        
        private string MaskMobileNumber(string mobile)
        {
            if (string.IsNullOrWhiteSpace(mobile) || mobile.Length < 9)
            {
                return string.Empty;
            }

            return mobile.Remove(4, 3).Insert(4, "***");
        }

    }
}