namespace Bookworms_Online.Models
{
    public class SessionTimeoutMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<SessionTimeoutMiddleware> _logger;

        public SessionTimeoutMiddleware(RequestDelegate next, ILogger<SessionTimeoutMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (context.User.Identity.IsAuthenticated)
            {
                if (context.Session.IsAvailable)
                {
                    string userId = context.Session.GetString("User Id");
                    _logger.LogInformation($"Authenticated User Id: {userId}");

                    if (userId == null)
                    {
                        _logger.LogInformation("Session expired for authenticated user, redirecting to login");
                        context.Response.Redirect("/Account/Login");
                        return;
                    }
                }
            }

            await _next(context);
        }
    }
}
