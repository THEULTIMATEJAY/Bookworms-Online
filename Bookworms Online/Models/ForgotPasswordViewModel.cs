using System.ComponentModel.DataAnnotations;
namespace Bookworms_Online.Models
{
    public class ForgotPasswordViewModel
    {
        [Required, EmailAddress]
        public string Email { get; set; }
    }
}
