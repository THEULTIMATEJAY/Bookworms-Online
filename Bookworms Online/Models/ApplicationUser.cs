using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
namespace Bookworms_Online.Models
{
    public class ApplicationUser : IdentityUser
    {
        [Required, StringLength(50)]
        public string FirstName { get; set; }

        [Required, StringLength(50)]
        public string LastName { get; set; }

        //[Required, StringLength(16)]
        [Required,MaxLength(256)]
        public string CreditCardNo { get; set; }

        [Required, StringLength(8)]
        public string MobileNumber { get; set; }

        [Required]
        public string BillingAddress { get; set; }

        [Required]
        public string ShippingAddress { get; set; }

        public string PhotoPath { get; set; }
        public bool IsTwoFactorEnabled { get; set; }
        public string? CurrentSessionId { get; set; }
        public DateTime? LastPasswordChangeDate { get; set; }

    }
    
}
