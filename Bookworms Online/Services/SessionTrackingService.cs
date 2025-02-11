using System.Collections.Concurrent;
namespace Bookworms_Online.Services
{
    public class SessionTrackingService
    {
        private static readonly ConcurrentDictionary<string, string> UserSessions = new();

        public bool IsUserLoggedInElsewhere(string userId, string sessionId)
        {
            return UserSessions.TryGetValue(userId, out var existingSession) && existingSession != sessionId;
        }

        public void TrackSession(string userId, string sessionId)
        {
            UserSessions[userId] = sessionId;
        }

        public void RemoveSession(string userId)
        {
            UserSessions.TryRemove(userId, out _);
        }

    }
}
