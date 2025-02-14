using Bookworms_Online.Data;
using Bookworms_Online.Models;
using Bookworms_Online.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.IO;
using System.Threading.Tasks;
using reCAPTCHA.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Authorization;
using System.Linq;
using Microsoft.EntityFrameworkCore;
using System.Web;
namespace Bookworms_Online.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ReCaptchaService _reCaptchaService;
        private readonly EncryptionService _encryptionService;
        private readonly IWebHostEnvironment _webHostEnvironment;
        private readonly ILogger<AccountController> _logger;
        private readonly EmailService _emailService;
        private readonly PasswordHistoryService _passwordHistoryService;
        private readonly ApplicationDbContext _context;
        private readonly AuditLogService _auditLogService;

        public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, EncryptionService encryptionService, IWebHostEnvironment webHostEnvironment, ReCaptchaService reCaptchaService, EmailService emailService, PasswordHistoryService passwordHistoryService, ILogger<AccountController> logger,AuditLogService auditLogService,ApplicationDbContext context)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _reCaptchaService = reCaptchaService;
            _encryptionService = encryptionService;
            _webHostEnvironment = webHostEnvironment;
            _logger = logger;
            _emailService = emailService;
            _passwordHistoryService = passwordHistoryService;
            _context = context;
            _auditLogService = auditLogService ?? throw new ArgumentNullException(nameof(auditLogService));



        }
        [AllowAnonymous]
        [HttpGet]
        public async Task<IActionResult> ResetTestPassword()
        {
            var user = await _userManager.FindByEmailAsync("jaydenng088@gmail.com");
            if (user == null)
            {
                return Content("User not found.");
            }

            string resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
            var result = await _userManager.ResetPasswordAsync(user, resetToken, "Test@12345");

            if (result.Succeeded)
            {
                return Content("Password reset successful. Use 'Test@12345' to log in.");
            }

            return Content("Password reset failed.");
        }

        [AllowAnonymous]
        [HttpGet]
        public IActionResult Login(string? returnUrl = null)
        {
            return View(new LoginViewModel { ReturnUrl = returnUrl });
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
        {
            

            _logger.LogInformation("Login attempt for: " + model.Email);
            ViewData["ReturnUrl"] = returnUrl;

            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Model state is invalid.");
                foreach (var key in ModelState.Keys)
                {
                    if (ModelState[key]?.Errors != null)
                    {
                        foreach (var error in ModelState[key].Errors)
                        {
                            _logger.LogError($"Validation error in {key}: {error.ErrorMessage}");
                        }
                    }
                }
                return View(model);
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                
                _logger.LogWarning($"Login failed: No user found with email {model.Email}");
                ModelState.AddModelError("", "Invalid login attempt.");
                return View(model);
            }
            if (await _userManager.IsLockedOutAsync(user))
            {
                _logger.LogWarning($"Login failed: Account locked for {user.Email}");
                ModelState.AddModelError("", "Account locked due to multiple failed login attempts.");
                return View(model);
            }
            
            bool isPasswordCorrect = await _userManager.CheckPasswordAsync(user, model.Password);
            if (!isPasswordCorrect)
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var resetLink = Url.Action("ResetPassword", "Account", new { token, email = model.Email }, Request.Scheme);
                await _userManager.AccessFailedAsync(user);
                if (user.Email != null)
                {
                    await _emailService.SendEmailAsync(user.Email, "Password Reset Request",
                    $"Click <a href='{resetLink}'>here</a> to reset your password.");
                }
                else
                {
                    ModelState.AddModelError("", "Email not found.");
                    return View(model);
                }
                _logger.LogWarning($"Login failed: Incorrect password for {user.Email}");
                ModelState.AddModelError("", "Invalid login attempt.");
                return View(model);
            }
            //if (string.IsNullOrEmpty(user.CurrentSessionId))
            //{
            //    _logger.LogWarning($"Login failed: User {user.Email} is already logged in on another browser.");
            //    ModelState.AddModelError("", "You are already logged in on another browser.1");
            //    return View(model);
            //}
            // Handle multiple browser logins
            var currentSessionId = HttpContext.Session.GetString("CurrentSessionId");
            if (user.CurrentSessionId != null && user.CurrentSessionId != currentSessionId)
            {
                _logger.LogWarning($"User {user.Email} is logged in on another browser. Invalidating the earlier session.");

                // Invalidate the previous session
                await InvalidateOldSessionAsync(user);
                await _signInManager.SignOutAsync();
                HttpContext.Session.Clear();
                Response.Cookies.Delete(".AspNetCore.Identity.Application");
                await _userManager.UpdateAsync(user);


                HttpContext.Response.Redirect("/Account/Login");
                //return View(model);
            }
            HttpContext.Session.Clear();
            Response.Cookies.Delete(".AspNetCore.Identity.Application");
            var result = await _signInManager.PasswordSignInAsync(user, model.Password, false, true);
            if (result.Succeeded)
            {

                //var currentSessionId = HttpContext.Session.GetString("CurrentSessionId");
                // Generate a new session ID
                var sessionId = Guid.NewGuid().ToString();
                _logger.LogInformation($"Session ID: {sessionId}");
                //_logger.LogInformation($"Current Session ID: {currentSessionId}");
               
                HttpContext.Session.SetString("CurrentSessionId", sessionId);

                
                HttpContext.Session.SetString("UserId", user.Id);
                HttpContext.Session.SetString("User Email", user.Email);
                _logger.LogInformation($"Session data set for user {user.Email}: UserId = {user.Id}, SessionId = {sessionId}");
                // Update the user's session ID in the database
                user.CurrentSessionId = sessionId;
                await _signInManager.PasswordSignInAsync(user, model.Password, false, true);

                await _userManager.UpdateAsync(user);
                await _auditLogService.LogActionAsync(user.Id, "Login Successful");
                
                if (user.IsTwoFactorEnabled)
                {
                    // Generate OTP and store it in the session
                    var otp = GenerateOTP(); // Implement this method to generate a random OTP
                    HttpContext.Session.SetString("OTP", otp);
                    HttpContext.Session.SetString("UserEmail", user.Email);

                    // Send OTP to the user's email
                    await _emailService.SendEmailAsync(user.Email, "Your OTP for 2FA",
                        $"Your OTP is: {otp}");

                    // Redirect to Verify2FA page
                    return RedirectToAction("Verify2FA");
                }

                return RedirectToAction("Index", "Home");
            }
            else if (result.IsLockedOut)
            {
                _logger.LogWarning($"Login failed: Account locked for {user.Email}");
                await _auditLogService.LogActionAsync(user.Id, "Account Locked");
                ModelState.AddModelError("", "Account locked due to multiple failed login attempts.");
            }
            else
            {
                _logger.LogWarning($"Login failed: Invalid credentials for {user.Email}");
                await _auditLogService.LogActionAsync(user.Id, "Failed Login Attempt");
                ModelState.AddModelError("", "Invalid login attempt.");
            }
            
            return View(model);
        }
        private string GenerateOTP()
        {
            var random = new Random();
            return random.Next(100000, 999999).ToString(); // 6-digit OTP
        }
        private async Task InvalidateOldSessionAsync(ApplicationUser user)
        {
            // If user has a session stored in the database, clear it
            if (!string.IsNullOrEmpty(user.CurrentSessionId))
            {
                _logger.LogInformation($"Invalidating session {user.CurrentSessionId} for user {user.Email}");

                // Perform any session invalidation logic here, for example, removing session data from a database or cache

                // Update the user's session ID to null or a default value in the database
                user.CurrentSessionId = null;
                await _userManager.UpdateAsync(user);
            }
        }
        [AllowAnonymous]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            var userId = HttpContext.Session.GetString("UserId");
            if (userId != null)
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user != null)
                {
                    user.CurrentSessionId = null;
                    await _userManager.UpdateAsync(user);
                }
                await _auditLogService.LogActionAsync(userId, "Logout");
            }

            await _signInManager.SignOutAsync();
            HttpContext.Session.Clear();
            Response.Cookies.Delete(".AspNetCore.Identity.Application");
            return RedirectToAction("Login", "Account");
        }

        [AllowAnonymous]
        //Register
        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }
        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid)
            {
                // 🔍 Debug: Log errors if model binding fails
                foreach (var modelState in ModelState.Values)
                {
                    foreach (var error in modelState.Errors)
                    {
                        _logger.LogError(error.ErrorMessage);
                    }
                }

                return View(model);
            }
            _logger.LogInformation($"Received Registration Data: {model.FirstName}, {model.LastName}, {model.Email}");

            

            // Check if email already exists
            var existingUser = await _userManager.FindByEmailAsync(model.Email);
            if (existingUser != null)
            {
                ModelState.AddModelError("Email", "Email already in use.");
                return View(model);
            }

            // Encrypt Credit Card Number
            string encryptedCardNumber = _encryptionService.Encrypt(model.CreditCardNo);

            string photoPath = string.Empty;
            if (model.Photo != null && model.Photo.Length > 0)
            {
                // Extract values
                string fileName = model.Photo.FileName;
                string extension = Path.GetExtension(fileName).Trim().ToLowerInvariant(); // Convert to lowercase & trim spaces
                string contentType = model.Photo.ContentType.ToLowerInvariant();
                long fileSize = model.Photo.Length;

                // Log details
                _logger.LogInformation($"[UPLOAD DEBUG] File Name: {fileName}");
                _logger.LogInformation($"[UPLOAD DEBUG] Extracted File Extension: {extension}");
                _logger.LogInformation($"[UPLOAD DEBUG] MIME Type: {contentType}");
                _logger.LogInformation($"[UPLOAD DEBUG] File Size: {fileSize} bytes");

                // Allowed file types
                var allowedExtensions = new[] { ".jpg", ".jpeg", ".png" };
                var allowedMimeTypes = new[] { "image/jpeg", "image/png" };

                // Check extension
                if (!allowedExtensions.Contains(extension))
                {
                    _logger.LogError($"[UPLOAD ERROR] Invalid file extension detected: {extension}");
                    ModelState.AddModelError("Photo", "Please upload a valid JPG or PNG file.");
                    return View(model);
                }

                // Check MIME type
                if (!allowedMimeTypes.Contains(contentType))
                {
                    _logger.LogError($"[UPLOAD ERROR] Invalid MIME type detected: {contentType}");
                    ModelState.AddModelError("Photo", "Invalid file type. Please upload a valid JPG or PNG file.");
                    return View(model);
                }

                // Save File
                string uploadDir = Path.Combine(_webHostEnvironment.WebRootPath, "uploads");
                if (!Directory.Exists(uploadDir))
                {
                    Directory.CreateDirectory(uploadDir);
                }

                photoPath = Path.Combine("uploads", Path.GetRandomFileName() + extension);
                using (var fileStream = new FileStream(Path.Combine(_webHostEnvironment.WebRootPath, photoPath), FileMode.Create))
                {
                    await model.Photo.CopyToAsync(fileStream);
                }
                _logger.LogInformation("[UPLOAD SUCCESS] File uploaded successfully.");

            }
            else
            {
                _logger.LogWarning("Photo file is null or empty.");
            }

            var user = new ApplicationUser
            {
                FirstName = HttpUtility.HtmlEncode( model.FirstName ),
                LastName = HttpUtility.HtmlEncode(model.LastName),
                CreditCardNo = encryptedCardNumber,
                MobileNumber = model.MobileNo,
                BillingAddress = HttpUtility.HtmlEncode(model.BillingAddress),
                ShippingAddress = HttpUtility.HtmlEncode(model.ShippingAddress),
                Email = model.Email,
                UserName = HttpUtility.HtmlEncode(model.Email),
                PhotoPath = HttpUtility.HtmlEncode(photoPath)
            };
            _logger.LogInformation($"Password Hash: {_userManager.PasswordHasher.HashPassword(user, model.Password)}");
            var result = await _userManager.CreateAsync(user, model.Password);
            _logger.LogInformation($"Generated password hash: {user.PasswordHash}");
            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(user, isPersistent: false);
                return RedirectToAction("Index", "Home");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }

            return View(model);
        }
        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Enable2FA()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                _logger.LogError("User not found.");
                return RedirectToAction("Index","Home");
            }

            user.IsTwoFactorEnabled = true;
            var result = await _userManager.UpdateAsync(user);

            if (result.Succeeded)
            {
                _logger.LogInformation($"2FA enabled for {user.Email}");
            }
            else
            {
                _logger.LogError($"Error enabling 2FA: {string.Join(", ", result.Errors.Select(e => e.Description))}");
            }

            return RedirectToAction("Manage2FA");
        }

        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Disable2FA()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                _logger.LogError("User not found.");
                return RedirectToAction("Index","Home");
            }

            user.IsTwoFactorEnabled = false;
            var result = await _userManager.UpdateAsync(user);

            if (result.Succeeded)
            {
                _logger.LogInformation($"2FA disabled for {user.Email}");
            }
            else
            {
                _logger.LogError($"Error disabling 2FA: {string.Join(", ", result.Errors.Select(e => e.Description))}");
            }

            return RedirectToAction("Manage2FA");
        }
        [Authorize]
        [HttpGet]
        public async Task<IActionResult> Manage2FA()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user != null)
            {
                ViewData["IsTwoFactorEnabled"] = user.IsTwoFactorEnabled;
            }
            return View();
        }
        [HttpGet]
        public IActionResult Verify2FA()
        {
            return View(new TwoFactorViewModel());
        }

        [HttpPost]
        public async Task<IActionResult> Verify2FA(TwoFactorViewModel model)
        {
            var storedOtp = HttpContext.Session.GetString("OTP");
            var userEmail = HttpContext.Session.GetString("UserEmail");

            if (storedOtp == model.OTP)
            {
                HttpContext.Session.Remove("OTP");
                HttpContext.Session.Remove("UserEmail");
                var user = await _userManager.FindByEmailAsync(userEmail);
                if (user != null)
                {
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    return RedirectToAction("Index", "Home");
                }
            }

            ModelState.AddModelError("", "Invalid OTP. Please try again.");
            return View(model);
        }
        [AllowAnonymous]
        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }
        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                ModelState.AddModelError("", "Email not found.");
                return View(model);
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var resetLink = Url.Action("ResetPassword", "Account", new { token, email = model.Email }, Request.Scheme);

            await _emailService.SendEmailAsync(user.Email, "Password Reset Request",
                $"Click <a href='{resetLink}'>here</a> to reset your password.");

            return View("ForgotPasswordConfirmation");
        }
        [AllowAnonymous]
        [HttpGet]
        public IActionResult ResetPassword(string token, string email)
        {
            return View(new ResetPasswordViewModel { Token = token, Email = email });
        }
        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                ModelState.AddModelError("", "Invalid request.");
                return View(model);
            }

            var result = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);
            if (result.Succeeded)
            {
                await _auditLogService.LogActionAsync(user.Id, "Password Reset");
                TempData["SuccessMessage"] = "Your password has been reset successfully. You can now log in with your new password.";
                return RedirectToAction("Login", "Account");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }

            return View(model);
        }
        [Authorize]
        [HttpGet]
        public IActionResult ChangePassword()
        {
            return View();
        }

        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToAction("Login", "Account");
            }
            var passwordHistories = await _context.PasswordHistories
        .Where(ph => ph.UserId == user.Id)
        .OrderByDescending(ph => ph.CreatedAt)
        .Take(2)
        .ToListAsync();

            foreach (var history in passwordHistories)
            {
                var passwordHasher = new PasswordHasher<ApplicationUser>();
                if (passwordHasher.VerifyHashedPassword(user, history.PasswordHash, model.NewPassword) == PasswordVerificationResult.Success)
                {
                    ModelState.AddModelError("", "You cannot reuse your last two passwords.");
                    return View(model);
                }
            }
            if (user.LastPasswordChangeDate.HasValue && (DateTime.UtcNow - user.LastPasswordChangeDate.Value).TotalMinutes < 30)
            {
                ModelState.AddModelError("", "You must wait at least 30 minutes before changing your password again.");
                return View(model);
            }

            var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
            if (result.Succeeded)
            {
                // Save the new password hash to history
                var newPasswordHash = _userManager.PasswordHasher.HashPassword(user, model.NewPassword);
                _context.PasswordHistories.Add(new PasswordHistory { UserId = user.Id, PasswordHash = newPasswordHash, CreatedAt = DateTime.UtcNow });
                await _context.SaveChangesAsync();
                user.LastPasswordChangeDate = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);

                _logger.LogInformation("User changed their password successfully.");
                TempData["SuccessMessage"] = "Your password has been changed successfully.";
                return RedirectToAction("Index", "Home");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }

            return View(model);
        }
    }

}

    

