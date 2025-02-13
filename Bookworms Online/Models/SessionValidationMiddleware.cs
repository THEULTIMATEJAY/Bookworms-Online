using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;

namespace Bookworms_Online.Models
{
    public class SessionValidationMiddleware
    {
        private readonly RequestDelegate _next;

        public SessionValidationMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, UserManager<ApplicationUser> userManager)
        {
            var userId = context.Session.GetString("UserId");
            if (userId != null)
            {
                var user = await userManager.FindByIdAsync(userId);
                if (user != null)
                {
                    var sessionId = context.Session.GetString("CurrentSessionId");
                    if (user.CurrentSessionId != sessionId)
                    {
                        // The IDs do not match, meaning another login has occurred.
                        await context.SignOutAsync();
                        context.Session.Clear();
                        context.Response.Redirect("/Account/Login");
                        return;
                    }
                }
            }

            await _next(context);
        }
    }
}
