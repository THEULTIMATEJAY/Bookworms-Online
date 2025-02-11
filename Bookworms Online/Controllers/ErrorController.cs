using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using System.Net;
namespace Bookworms_Online.Controllers
{
    public class ErrorController : Controller
    {
        [Route("Error/{statusCode}")]
        public IActionResult HttpStatusCodeHandler(int statusCode)
        {
            var statusMessage = statusCode switch
            {
                (int)HttpStatusCode.NotFound => "Sorry, the page you requested was not found.",
                (int)HttpStatusCode.Forbidden => "Access denied. You do not have permission to view this page.",
                _ => "An unexpected error occurred. Please try again later."
            };

            ViewBag.StatusCode = statusCode;
            ViewBag.StatusMessage = statusMessage;
            return View("ErrorPage");
        }

        [Route("Error")]
        public IActionResult ExceptionHandler()
        {
            var exceptionFeature = HttpContext.Features.Get<IExceptionHandlerPathFeature>();
            ViewBag.ErrorMessage = "An unexpected error occurred. Please contact support.";

            // Log the error (can be extended to a logging service)
            Console.WriteLine($"Exception: {exceptionFeature?.Error}");

            return View("ErrorPage");
        }
    }
}
