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
        private readonly SessionTrackingService _sessionTrackingService;
        private readonly AuditLogService _auditLogService;

        public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, EncryptionService encryptionService, IWebHostEnvironment webHostEnvironment, ReCaptchaService reCaptchaService, EmailService emailService, PasswordHistoryService passwordHistoryService, SessionTrackingService sessionTrackingService, ILogger<AccountController> logger,AuditLogService auditLogService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _reCaptchaService = reCaptchaService;
            _encryptionService = encryptionService;
            _webHostEnvironment = webHostEnvironment;
            _logger = logger;
            _emailService = emailService;
            _passwordHistoryService = passwordHistoryService;
            _sessionTrackingService = sessionTrackingService;
            _auditLogService = auditLogService ?? throw new ArgumentNullException(nameof(auditLogService));



        }
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
            bool isPasswordCorrect = await _userManager.CheckPasswordAsync(user, model.Password);
            if (!isPasswordCorrect)
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var resetLink = Url.Action("ResetPassword", "Account", new { token, email = model.Email }, Request.Scheme);

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

            var result = await _signInManager.PasswordSignInAsync(user, model.Password, false, true);
            if (result.Succeeded)
            {
                _logger.LogInformation($"Login successful: {user.Email}");
                await _auditLogService.LogActionAsync(user.Id, "Login Successful");
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

        [HttpPost]
        public async Task<IActionResult> Logout()
        {
            var userId = HttpContext.Session.GetString("UserId");
            if (userId != null)
            {
                await _auditLogService.LogActionAsync(userId, "Logout");
            }

            await _signInManager.SignOutAsync();
            HttpContext.Session.Clear();
            return RedirectToAction("Login", "Account");
        }


        //Register
        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

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
                FirstName = model.FirstName,
                LastName = model.LastName,
                CreditCardNo = encryptedCardNumber,
                MobileNumber = model.MobileNo,
                BillingAddress = model.BillingAddress,
                ShippingAddress = model.ShippingAddress,
                Email = model.Email,
                UserName = model.Email,
                PhotoPath = photoPath
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
        public async Task<IActionResult> Enable2FA()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user != null)
            {
                user.IsTwoFactorEnabled = true;
                await _userManager.UpdateAsync(user);
            }
            return RedirectToAction("Manage2FA");
        }

        [HttpPost]
        public async Task<IActionResult> Disable2FA()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user != null)
            {
                user.IsTwoFactorEnabled = false;
                await _userManager.UpdateAsync(user);
            }
            return RedirectToAction("Manage2FA");
        }
        [HttpGet]
        public IActionResult Verify2FA()
        {
            return View(new TwoFactorViewModel());
        }

        [HttpPost]
        public IActionResult Verify2FA(TwoFactorViewModel model)
        {
            var storedOtp = HttpContext.Session.GetString("OTP");
            var userEmail = HttpContext.Session.GetString("UserEmail");

            if (storedOtp == model.OTP)
            {
                HttpContext.Session.Remove("OTP");
                return RedirectToAction("Index", "Home");
            }

            ModelState.AddModelError("", "Invalid OTP. Please try again.");
            return View(model);
        }
        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }

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
        [HttpGet]
        public IActionResult ResetPassword(string token, string email)
        {
            return View(new ResetPasswordViewModel { Token = token, Email = email });
        }

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
                return RedirectToAction("Login", "Account");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }

            return View(model);
        }
    }

}

    

