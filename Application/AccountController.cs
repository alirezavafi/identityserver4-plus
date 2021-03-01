using IdentityServer4;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Serilog;
using Serilog.Context;
using SSO.Identity;
using SSO.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AutoWrapper.Wrappers;

namespace SSO.Controllers
{
    [Route("sso/v1/account")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly ApplicationUserManager _userManager;
        private readonly IOtpService _otp;
        private readonly IIdentityServerInteractionService _identityServerInteractionService;
        private readonly IEventService _events;
        private readonly ISmsServices _smsServices; 
        private readonly ILogger _logger;
        private readonly IConfiguration configuration;

        public const string VisitorCodeCheckActionName = "VisitorCodeCheck";

        public AccountController(
               ApplicationUserManager userManager,
               IOtpService otp,
               IIdentityServerInteractionService identityServerInteractionService,
               IEventService events,
               ISmsServices smsServices,
               ILogger logger,
               IConfiguration configuration)
        {
            _userManager = userManager;
            _otp = otp;
            _identityServerInteractionService = identityServerInteractionService;
            _events = events;
            _smsServices = smsServices;
            _logger = logger;
            this.configuration = configuration;
        }

        [HttpPost("send-otp")]
        public async Task<IActionResult> SendOtpAsync(SendOtpModel model)
        {
            using var logContext = LogContext.PushProperty("MobileNumber", model.MobileNumber);

            var context = await _identityServerInteractionService.GetAuthorizationContextAsync(model.ReturnUrl);
            if (context == null)
            {
                _logger.Verbose("ReturnUrl invalid, cannot find authorization context", ModelState.Values);
                return BadRequest(Result.Failed(CoreLib.Error.Error.WithCode(CoreLib.Error.BaseErrorCodes.InvalidModel)));
            }

            if (!ModelState.IsValid)
            {
                _logger.Verbose("Invalid {@Input}", ModelState.Values);
                return BadRequest(Result.Failed(CoreLib.Error.Error.WithCode(ErrorCodes.InvalidModel)));
            }

            var existingUser = await _userManager.FindFirstByPhoneNumberAsync(model.MobileNumber);
            string otpCode;
            if (existingUser == null)
            {
                _logger.Information("User not exists, trying to authenticate for registration", ModelState.Values);
                otpCode = _otp.GenerateOtp(model.MobileNumber);
            }
            else
            {
                _logger.Information("User already exists, generating user otp", ModelState.Values);
                otpCode = await _userManager.GenerateChangePhoneNumberTokenAsync(existingUser, model.MobileNumber);
            }

            await this.SendOtpCode(model.MobileNumber, otpCode);
            return Ok(Result.Successful());
        }

        private async Task SendOtpCode(string mobileNumber, string otpCode)
        {
            _logger.Verbose("Sending {@Otp}", otpCode);
            var result = await _smsServices.Send(new OutgoingSms()
            {
                Reciever = mobileNumber,
                Text = $"اقتصاد بیدار\r\nکد فعال سازی شما: {otpCode}"
            });
            if (!result.Success)
            {
                throw new InvalidOperationException("cannot send message");
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> LoginAsync(LoginModel model)
        {
            using var logContext = LogContext.PushProperty("MobileNumber", model.MobileNumber);

            var context = await _identityServerInteractionService.GetAuthorizationContextAsync(model.ReturnUrl);
            if (context == null)
            {
                _logger.Verbose("ReturnUrl invalid, cannot find authorization context", ModelState.Values);
               throw new 
            }

            if (!ModelState.IsValid)
            {
                _logger.Verbose("Invalid {@Input}", ModelState.Values);
                throw new ApiProblemDetailsException(ModelState);
            }

            try
            {
                Serilog.Log.Information("Checking for visitor Code {@Model} {@Action}", model, VisitorCodeCheckActionName);
                if (!string.IsNullOrWhiteSpace(model.ReturnUrl))
                {
                    var arguments = model.ReturnUrl.Split("?")[1].Split('&').Select(q => q.Split('=')).ToDictionary(q => q.FirstOrDefault(), q => q.Skip(1).FirstOrDefault());
                    if (arguments.ContainsKey("visitorCode"))
                    {
                        Serilog.Log.Information("Setting {@VisitorCode} {@Action}", arguments["visitorCode"], VisitorCodeCheckActionName);
                        model.VisitorCode = WebUtility.UrlDecode(arguments["visitorCode"])?.Replace("\"","");
                    }
                    else
                    {
                        Serilog.Log.Information("No visitor {@Action}", VisitorCodeCheckActionName);
                    }
                }
            }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex, "Cannot set visitorCode for {@Model} {@Action}", model, VisitorCodeCheckActionName);
            }

            var existingUsers = await _userManager.FindAllByPhoneNumberAsync(model.MobileNumber);

            var existingUser = existingUsers.FirstOrDefault();
            if (existingUser == null)
            {
                if (_otp.IsValidOtp(model.MobileNumber, model.OtpCode))
                {
                    _logger.Information("User not exists, Visitor code accepted if specified {@Action}", VisitorCodeCheckActionName);
                    await this.SignInPartial(model.MobileNumber, model.VisitorCode);
                    return new LoginResult() {MustRegister = true};
                }
                else
                {
                    _logger.Information("Invalid otp for new user");
                    return Unauthorized(Result.Failed(CoreLib.Error.Error.WithCode(ErrorCodes.InvalidUsernameOrPassword), "کد وارد شده صحیح نمی باشد"));
                }
            }
            else
            {
                var isUserLockedOut = await _userManager.IsLockedOutAsync(existingUser);
                if (isUserLockedOut)
                {
                    _logger.Information("{@User} locked-out prior to anomaly", existingUser);
                    await _events.RaiseAsync(new UserLoginFailureEvent(model.MobileNumber, "account locked-out", clientId: context?.Client.ClientId));
                    await _userManager.AccessFailedAsync(existingUser);
                    return Unauthorized(Result.Failed(CoreLib.Error.Error.WithCode(ErrorCodes.UserLockedOutOrDeactivated), "کاربر غیر فعال می باشد"));
                }
                var isUserLogonEnabled = await _userManager.IsUserLogonEnabledAsync(existingUser);
                if (!isUserLogonEnabled)
                {
                    _logger.Information("{@User} logon is not enabled", existingUser);
                    await _events.RaiseAsync(new UserLoginFailureEvent(model.MobileNumber, "account logon not enabled", clientId: context?.Client.ClientId));
                    await _userManager.AccessFailedAsync(existingUser);
                    return Unauthorized(Result.Failed(CoreLib.Error.Error.WithCode(ErrorCodes.UserLockedOutOrDeactivated), "کاربر غیر فعال می باشد"));
                }

                var isValidOtp = await _userManager.VerifyChangePhoneNumberTokenAsync(existingUser, model.OtpCode, model.MobileNumber);
                if (isValidOtp)
                {
                    await this.SignInPartial(model.MobileNumber, model.VisitorCode);
                    return Ok(Result<LoginResult>.Successful(new LoginResult()
                    {
                        MustSelectUser = true,
                        AvailableUsers = existingUsers.Select(x => new AvailableUser()
                        {
                            FullName = $"{x.FirstName} {x.LastName}",
                            Username = x.UserName
                        }).ToList(),
                    }));
                }
                else
                {
                    _logger.Information("Invalid otp for user {@User}", existingUser);
                    await _events.RaiseAsync(new UserLoginFailureEvent(model.MobileNumber, "invalid otp", clientId: context?.Client.ClientId));
                    await _userManager.AccessFailedAsync(existingUser);
                    return Unauthorized(Result.Failed(CoreLib.Error.Error.WithCode(ErrorCodes.InvalidUsernameOrPassword), "کد وارد شده صحیح نمی باشد"));
                }
            }
        }

        private async Task SignInPartial(string mobileNumber, string visitorCode)
        {
            var claims = new List<Claim>()
                                {
                                    new Claim(Constants.Claims.MobileNumber, mobileNumber),
                                };
            if (!string.IsNullOrWhiteSpace(visitorCode))
            {
                claims.Add(new Claim(Constants.Claims.VisitorCode, visitorCode));
            }
            var claimsIdentity = new ClaimsIdentity(claims, Constants.PartialAuthenticationSchemeName);
            var props = new AuthenticationProperties();
            await HttpContext.SignInAsync(
                        scheme: Constants.PartialAuthenticationSchemeName,
                        properties: props,
                        principal: new ClaimsPrincipal(claimsIdentity));

            _logger.Information("User patially authenticated and must register to continue");
        }

        private async Task SignIn(ApplicationUser user, string visitorCode)
        {
            var props = new AuthenticationProperties();
            var claims = new List<Claim>() {
                new Claim(Constants.Claims.MobileNumber, user.MobileNumber),
                new Claim(Constants.Claims.NationalCode, user.NationalCode),
                new Claim("given_name", user.FirstName),
                new Claim("family_name", user.LastName),
            };
            var isuser = new IdentityServerUser(user.Id.ToString())
            {
                DisplayName = $"{user.FirstName} {user.LastName}",
                AdditionalClaims = claims
            };
            
            await _userManager.SetSuccessfulLogin(user);
            await _userManager.ResetAccessFailedCountAsync(user);
            var userPrincipal = isuser.CreatePrincipal();
            await HttpContext.SignInAsync(Constants.DefaultAuthenticationSchemeName, userPrincipal, props);
        }

        [HttpPost("select-user")]
        public async Task<IActionResult> SelectUserAsync(SelectUserModel model)
        {
            _logger.Verbose("Trying to authenticate user partially");
            var authResult = await HttpContext.AuthenticateAsync(Constants.PartialAuthenticationSchemeName);
            var authUser = authResult.Principal;
            if (!authResult.Succeeded || authResult.Ticket.AuthenticationScheme != Constants.PartialAuthenticationSchemeName)
            {
                _logger.Information("Cannot authenticate user {@Result}", authResult);
                return Unauthorized(Result.Failed(CoreLib.Error.Error.WithCode(ErrorCodes.GeneralUnauthorizedError)));
            }

            var mobileNumber = authUser.FindFirstValue(Constants.Claims.MobileNumber);
            using var logContext2 = LogContext.PushProperty("MobileNumber", mobileNumber);

            var context = await _identityServerInteractionService.GetAuthorizationContextAsync(model.ReturnUrl);
            if (context == null)
            {
                _logger.Verbose("ReturnUrl invalid, cannot find authorization context", ModelState.Values);
                return BadRequest(Result.Failed(CoreLib.Error.Error.WithCode(CoreLib.Error.BaseErrorCodes.InvalidModel)));
            }

            if (!ModelState.IsValid)
            {
                _logger.Verbose("Invalid {@Input}", ModelState.Values);
                return BadRequest(Result.Failed(CoreLib.Error.Error.WithCode(CoreLib.Error.BaseErrorCodes.InvalidModel)));
            }

            var existingUser = await _userManager.FindByNameAsync(model.Username);
            if (existingUser == null)
            {
                _logger.Warning("Invalid user, cannot find user");
                return BadRequest(Result.Failed(CoreLib.Error.Error.WithCode(CoreLib.Error.BaseErrorCodes.InvalidModel)));
            }

            if (existingUser.MobileNumber != mobileNumber)
            {
                _logger.Warning("Selected {@User} does not belong to mobile number", existingUser);
                return BadRequest(Result.Failed(CoreLib.Error.Error.WithCode(CoreLib.Error.BaseErrorCodes.InvalidModel)));
            }

            var isUserLockedOut = await _userManager.IsLockedOutAsync(existingUser);
            if (isUserLockedOut)
            {
                _logger.Information("{@User} locked-out prior to anomaly", existingUser);
                await _events.RaiseAsync(new UserLoginFailureEvent(mobileNumber, "account locked-out", clientId: context?.Client.ClientId));
                await _userManager.AccessFailedAsync(existingUser);
                return Unauthorized(Result.Failed(CoreLib.Error.Error.WithData(ErrorCodes.UserLockedOutOrDeactivated, new[] { "کاربر غیر فعال می باشد" })));
            }
            var isUserLogonEnabled = await _userManager.IsUserLogonEnabledAsync(existingUser);
            if (!isUserLogonEnabled)
            {
                _logger.Information("{@User} logon is not enabled", existingUser);
                await _events.RaiseAsync(new UserLoginFailureEvent(mobileNumber, "account logon not enabled", clientId: context?.Client.ClientId));
                await _userManager.AccessFailedAsync(existingUser);
                return Unauthorized(Result.Failed(CoreLib.Error.Error.WithData(ErrorCodes.UserLockedOutOrDeactivated, new[] { "کاربر غیر فعال می باشد" })));
            }

            await CompleteSignIn(context, existingUser);
            return Ok(Result<LoginResult>.Successful(new LoginResult()
            {
                IsLoggedIn = true,
            }));
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync(RegisterModel model)
        {
            using var logContext = LogContext.PushProperty("NationalCode", model.NationalCode);

            var context = await _identityServerInteractionService.GetAuthorizationContextAsync(model.ReturnUrl);
            if (context == null)
            {
                _logger.Verbose("ReturnUrl invalid, cannot find authorization context", ModelState.Values);
                return BadRequest(Result.Failed(CoreLib.Error.Error.WithCode(CoreLib.Error.BaseErrorCodes.InvalidModel)));
            }

            if (!ModelState.IsValid)
            {
                _logger.Verbose("Invalid {@Input}", ModelState.Values);
                return BadRequest(Result.Failed(CoreLib.Error.Error.WithCode(CoreLib.Error.BaseErrorCodes.InvalidModel)));
            }

            _logger.Verbose("Trying to authenticate user partially");
            var authResult = await HttpContext.AuthenticateAsync(Constants.PartialAuthenticationSchemeName);
            var authUser = authResult.Principal;
            if (!authResult.Succeeded || authResult.Ticket.AuthenticationScheme != Constants.PartialAuthenticationSchemeName)
            {
                _logger.Information("Cannot authenticate user {@Result}", authResult);
                return Unauthorized(Result.Failed(CoreLib.Error.Error.WithCode(ErrorCodes.GeneralUnauthorizedError)));
            }

            var mobileNumber = authUser.FindFirstValue(Constants.Claims.MobileNumber);
            using var logContext2 = LogContext.PushProperty("MobileNumber", mobileNumber);

            var visitorCode = authUser.FindFirstValue(Constants.Claims.VisitorCode);
            var userName = model.NationalCode;
            var existingUser = await _userManager.FindByNameAsync(userName);
            if (existingUser != null)
            {
                _logger.Warning("{@User} already exists and cannot register", existingUser);
                return BadRequest(Result.Failed(CoreLib.Error.Error.WithCode(CoreLib.Error.BaseErrorCodes.Dublicate)));
            }

            var user = new ApplicationUser
            {
                UserName = userName,
                NormalizedUserName = userName,
                NationalCode = model.NationalCode,
                FirstName = model.FirstName,
                LastName = model.LastName,
                MobileNumber = mobileNumber,
                MobileNumberConfirmed = true,
            };
            var result = await _userManager.CreateAsync(user);
            if (result.Succeeded)
            {
                _logger.Information("Created new {@User}", user);
                await CompleteSignIn(context, user);
                return Ok(Result<LoginResult>.Successful(new LoginResult()
                {
                    IsLoggedIn = true,
                }));
            }
            else
            {
                _logger.Warning("{@User} failed to create with {@Result}", user, result);
                var duplicateError = new IdentityErrorDescriber().DuplicateUserName(user.UserName);
                var duplicateUser = await _userManager.FindByNameAsync(user.UserName);
                if (result.Errors.Any<IdentityError>(x => x.Code == duplicateError.Code))
                {
                    return BadRequest(Result.Failed(CoreLib.Error.Error.WithData(CoreLib.Error.BaseErrorCodes.Dublicate, new[] { MaskMobileNumber(duplicateUser?.MobileNumber) }), "کاربر دیگری با کد ملی وارد شده ثبت نام کرده است"));
                }

                return BadRequest(Result.Failed(CoreLib.Error.Error.WithCode(CoreLib.Error.BaseErrorCodes.InvalidModel)));
            }
        }

        private string MaskMobileNumber(string mobile)
        {
            if (string.IsNullOrWhiteSpace(mobile) || mobile.Length < 9)
            {
                return string.Empty;
            }

            return mobile.Remove(4, 3).Insert(4, "***");
        }

        private async Task CompleteSignIn(AuthorizationRequest context, ApplicationUser user)
        {
            var authResult = await HttpContext.AuthenticateAsync(Constants.PartialAuthenticationSchemeName);
            var authUser = authResult.Principal;
            var visitorCode = string.Empty;
            if (authResult.Succeeded && authResult.Ticket.AuthenticationScheme == Constants.PartialAuthenticationSchemeName)
            {
                visitorCode = authUser.FindFirstValue(Constants.Claims.VisitorCode);
            }

            await this.SignOutPartial();
            await this.SignIn(user, visitorCode);
            await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.NationalCode, user.UserName, clientId: context?.Client.ClientId));
            _logger.Information("{@User} logged-in", user);
        }

        private Task SignOutPartial()
        {
            return HttpContext.SignOutAsync(Constants.PartialAuthenticationSchemeName);
        }

        [HttpPost("logout")]
        public async Task<IActionResult> LogoutAsync(LogoutModel logoutModel)
        {
            var context = await _identityServerInteractionService.GetLogoutContextAsync(logoutModel?.LogoutId);
            if (context == null)
            {
                _logger.Verbose("Invalid logout Id {@LogoutId}", logoutModel?.LogoutId);
                return BadRequest();
            }

            await HttpContext.SignOutAsync(Constants.DefaultAuthenticationSchemeName);
            return new LogoutResult()
            {
                SignOutIFrameUrl = context.SignOutIFrameUrl,
                PostLogoutRedirectUrl = context.PostLogoutRedirectUri ?? configuration["Settings:DefaultPostLogoutUrl"],
            };
        }
    }
}