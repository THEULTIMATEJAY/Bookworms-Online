using System.ComponentModel.DataAnnotations;
using Bookworms_Online.Attributes;
namespace Bookworms_Online.Models
{
    public class RegisterViewModel
    {
        [Required, StringLength(50)]
        public string FirstName { get; set; }

        [Required, StringLength(50)]
        public string LastName { get; set; }

        [Required, DataType(DataType.CreditCard)]
        public string CreditCardNo { get; set; }

        [Required, StringLength(8)]
        public string MobileNo { get; set; }

        [Required]
        public string BillingAddress { get; set; }

        [Required]
        public string ShippingAddress { get; set; }

        [Required, EmailAddress]
        public string Email { get; set; }

        [Required, DataType(DataType.Password)]
        [PasswordStrength(ErrorMessage = "Password does not meet strength requirements.")]
        [StringLength(100, MinimumLength = 12, ErrorMessage = "Password must be at least 12 characters.")]
        public string Password { get; set; }

        [Required, DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "Passwords do not match.")]
        public string ConfirmPassword { get; set; }

        
        [DataType(DataType.Upload)]
        
        public IFormFile? Photo { get; set; }
    }
}
