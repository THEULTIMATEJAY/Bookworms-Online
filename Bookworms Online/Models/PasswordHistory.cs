namespace Bookworms_Online.Models
{
    public class PasswordHistory
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public string PasswordHash { get; set; }
        public DateTime CreatedAt { get; set; }

        public ApplicationUser User { get; set; }
    }
}
