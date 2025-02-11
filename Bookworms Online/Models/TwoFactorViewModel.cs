using System.ComponentModel.DataAnnotations;
namespace Bookworms_Online.Models
{
    public class TwoFactorViewModel
    {
        [Required]
        public string OTP { get; set; }

        public string Email { get; set; }
    }
}
