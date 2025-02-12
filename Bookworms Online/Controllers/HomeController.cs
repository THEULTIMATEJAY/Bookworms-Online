using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Bookworms_Online.Models;
using System.Threading.Tasks;
using Bookworms_Online.Services;
using Microsoft.AspNetCore.Authorization;

namespace Bookworms_Online.Controllers
{
    [AllowAnonymous]
    public class HomeController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly EncryptionService _encryptionService;


        public HomeController(UserManager<ApplicationUser> userManager, EncryptionService encryptionService)
        {
            _userManager = userManager;
            _encryptionService = encryptionService;
        }
        
        public async Task<IActionResult> Index()
        {
            ApplicationUser user = null;
            if (User.Identity.IsAuthenticated)
            {
                user = await _userManager.GetUserAsync(User);
                user.CreditCardNo = _encryptionService.Decrypt(user.CreditCardNo);
            }

            return View(user);
        }
    }
}
