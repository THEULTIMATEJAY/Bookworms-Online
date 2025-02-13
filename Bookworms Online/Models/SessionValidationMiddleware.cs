using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace Bookworms_Online.Models
{
    public class SessionValidationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<SessionValidationMiddleware> _logger;
        private readonly IServiceScopeFactory _scopeFactory;


        public SessionValidationMiddleware(RequestDelegate next,ILogger<SessionValidationMiddleware> logger,IServiceScopeFactory scopeFactory)
        {
            _next = next;
            _logger = logger;
            _scopeFactory = scopeFactory;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (context.Request.Path.StartsWithSegments("/Account/Login"))
            {
                await _next(context);
                return;
            }
            if (context.User.Identity.IsAuthenticated)
            {
                _logger.LogInformation("SessionValidationMiddleware: User is authenticated.");

                using (var scope = _scopeFactory.CreateScope())
                {
                    var _userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
                    var _signInManager = scope.ServiceProvider.GetRequiredService<SignInManager<ApplicationUser>>();

                    var userId = context.Session.GetString("UserId");
                    _logger.LogInformation($"SessionValidationMiddleware: UserId from session: {userId}");
                    if (userId != null)
                    {
                        var user = await _userManager.FindByIdAsync(userId);
                        if (user != null)
                        {

                            var sessionId = context.Session.GetString("CurrentSessionId");
                            _logger.LogInformation($"Session ID from session: {sessionId}");
                            _logger.LogInformation($"Session ID from database: {user.CurrentSessionId}");
                            if (user.CurrentSessionId != sessionId)
                            {
                                _logger.LogInformation($"Session mismatch detected for user: {user.UserName}. Logging out from expired session.");

                                // Sign out the user
                                await context.SignOutAsync();  // Use appropriate scheme
                                await _signInManager.SignOutAsync();  // Sign out using SignInManager

                                // Clear session and reset CurrentSessionId in user model
                                context.Session.Clear();
                                user.CurrentSessionId = null;  // Clear the session ID on the user model.
                                await _userManager.UpdateAsync(user);

                                
                                context.Response.Redirect("/Account/Login");
                                return;
                            }
                        }
                        else
                        {
                            _logger.LogInformation("SessionValidationMiddleware: User not found in database.");
                        }
                    }
                    else
                    {
                        _logger.LogInformation("SessionValidationMiddleware: UserId is null.");
                    }
                }
            }
            else
            {
                _logger.LogInformation("SessionValidationMiddleware: User is not authenticated.");
            }
            await _next(context);
        }
    }
}
