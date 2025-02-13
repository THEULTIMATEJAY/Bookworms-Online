using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Linq;
using System.Threading.Tasks;
using Bookworms_Online.Data;
using Microsoft.EntityFrameworkCore;
using Bookworms_Online.Models;
using Microsoft.AspNetCore.Identity;
namespace Bookworms_Online.Controllers
{
    [Authorize]
    public class AdminController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;


        public AdminController(ApplicationDbContext context,UserManager<ApplicationUser> userManager)
        {
            _context = context;
            _userManager = userManager;
        }

        public async Task<IActionResult> AuditLogs()
        {
            var userId = _userManager.GetUserId(User);

            // Retrieve only the audit logs for the current user
            var logs = await _context.AuditLogs
                .Where(log => log.UserId == userId)
                .OrderByDescending(l => l.Timestamp)
                .ToListAsync();

            return View(logs);
        }
    }
}
