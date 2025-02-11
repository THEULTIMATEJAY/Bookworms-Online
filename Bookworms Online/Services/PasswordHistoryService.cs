using System.Collections.Generic;
namespace Bookworms_Online.Services
{
    public class PasswordHistoryService
    {
        private static readonly Dictionary<string, List<string>> PasswordHistory = new();

        public bool IsPasswordReused(string userId, string newPassword)
        {
            if (PasswordHistory.TryGetValue(userId, out var passwords))
            {
                return passwords.Contains(newPassword);
            }
            return false;
        }

        public void StorePassword(string userId, string newPassword)
        {
            if (!PasswordHistory.ContainsKey(userId))
            {
                PasswordHistory[userId] = new List<string>();
            }

            var userPasswords = PasswordHistory[userId];
            if (userPasswords.Count >= 2)
            {
                userPasswords.RemoveAt(0); // Keep last 2 passwords
            }
            userPasswords.Add(newPassword);
        }
    }
}
