using System;
using System.ComponentModel.DataAnnotations;
namespace Bookworms_Online.Models
{
    public class AuditLog
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string UserId { get; set; }

        [Required]
        public string Action { get; set; } // e.g. "Login", "Failed Login", "Password Reset"

        [Required]
        public string IPAddress { get; set; }

        [Required]
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    }
}
