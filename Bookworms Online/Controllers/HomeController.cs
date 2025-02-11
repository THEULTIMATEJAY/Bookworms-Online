using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Bookworms_Online.Models;
using System.Threading.Tasks;

namespace Bookworms_Online.Controllers
{
    public class HomeController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public HomeController(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        public async Task<IActionResult> Index()
        {
            ApplicationUser user = null;
            if (User.Identity.IsAuthenticated)
            {
                user = await _userManager.GetUserAsync(User);
            }

            return View(user);
        }
    }
}
