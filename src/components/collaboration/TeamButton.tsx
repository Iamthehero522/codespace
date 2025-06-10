//src/components/collaboration/TeamButton.tsx
import React, { useState } from 'react';
import { Users, Crown, User } from 'lucide-react';

interface TeamUser {
  id: string;
  email: string;
  name: string;
  isOwner?: boolean;
  avatarUrl?: string;
}

interface TeamButtonProps {
  activeUsers: TeamUser[];
  ownerId?: string;
  isBlinking?: boolean;
}

export const TeamButton: React.FC<TeamButtonProps> = ({ 
  activeUsers, 
  ownerId,
  isBlinking = false 
}) => {
  const [showTooltip, setShowTooltip] = useState(false);

  const usersWithOwnership = activeUsers.map(user => ({
    ...user,
    isOwner: user.id === ownerId
  }));

  // Sort users with owner first, then alphabetically by name (fallback to email)
  const sortedUsers = [...usersWithOwnership].sort((a, b) => {
    if (a.isOwner && !b.isOwner) return -1;
    if (!a.isOwner && b.isOwner) return 1;
    const nameA = a.name || a.email || '';
    const nameB = b.name || b.email || '';
    return nameA.localeCompare(nameB);
  });

  const getInitials = (name?: string) => {
    if (!name) return '';
    return name
      .split(' ')
      .map(word => word.charAt(0))
      .join('')
      .toUpperCase()
      .slice(0, 2);
  };

  const getAvatarColor = (userId?: string) => {
    const colors = [
      'bg-blue-500',
      'bg-green-500',
      'bg-purple-500',
      'bg-pink-500',
      'bg-indigo-500',
      'bg-yellow-500',
      'bg-red-500',
      'bg-teal-500'
    ];
    if (!userId) {
      // fallback color for unknown users
      return 'bg-gray-500';
    }
    const sum = Array.from(userId).reduce((acc, char) => acc + char.charCodeAt(0), 0);
    return colors[sum % colors.length];
  };

  return (
    <div className="relative">
      <button
        className={`
          flex items-center space-x-2 px-4 py-2 rounded-lg transition-all duration-200
          ${isBlinking 
            ? 'bg-gradient-to-r from-blue-600 to-purple-600 animate-pulse shadow-lg' 
            : 'bg-gray-700 hover:bg-gray-600'
          }
          text-white border border-gray-600 hover:border-gray-500
        `}
        onMouseEnter={() => setShowTooltip(true)}
        onMouseLeave={() => setShowTooltip(false)}
        title={`${activeUsers.length} active user${activeUsers.length !== 1 ? 's' : ''}`}
      >
        <Users className={`w-4 h-4 ${isBlinking ? 'animate-bounce' : ''}`} />
        <span className="text-sm font-medium">{activeUsers.length}</span>
        {isBlinking && (
          <div className="absolute -top-1 -right-1 w-3 h-3 bg-green-400 rounded-full animate-ping"></div>
        )}
      </button>

      {/* Tooltip */}
      {showTooltip && activeUsers.length > 0 && (
        <div className="absolute top-full left-1/2 transform -translate-x-1/2 mt-2 z-50">
          <div className="bg-gray-800 rounded-lg shadow-xl border border-gray-700 p-4 min-w-[280px] max-w-[400px]">
            {/* Arrow */}
            <div className="absolute -top-2 left-1/2 transform -translate-x-1/2 w-4 h-4 bg-gray-800 border-l border-t border-gray-700 rotate-45"></div>
            
            <div className="relative">
              <h3 className="text-sm font-semibold text-white mb-3 flex items-center space-x-2">
                <Users className="w-4 h-4" />
                <span>Active Team Members ({activeUsers.length})</span>
              </h3>
              
              <div className="space-y-2 max-h-64 overflow-y-auto">
                {sortedUsers.map((user) => (
                  <div
                    key={user.id}
                    className="flex items-center space-x-3 p-2 rounded-lg hover:bg-gray-700 transition-colors"
                  >
                    {/* Avatar */}
                    <div className="relative">
                      {user.avatarUrl ? (
                        <img
                          src={user.avatarUrl}
                          alt={user.name}
                          className="w-8 h-8 rounded-full border-2 border-gray-600"
                        />
                      ) : (
                        <div className={`
                          w-8 h-8 rounded-full border-2 border-gray-600 flex items-center justify-center text-xs font-medium text-white
                          ${getAvatarColor(user.id)}
                        `}>
                          {getInitials(user.name)}
                        </div>
                      )}
                      
                      {/* Online indicator */}
                      <div className="absolute -bottom-0.5 -right-0.5 w-3 h-3 bg-green-400 border-2 border-gray-800 rounded-full"></div>
                    </div>

                    {/* User info */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center space-x-2">
                        <p className="text-sm font-medium text-white truncate">
                          {user.name}
                        </p>
                        {user.isOwner && (
                          <Crown className="w-4 h-4 text-yellow-400 flex-shrink-0" title="Owner" />
                        )}
                      </div>
                      <p className="text-xs text-gray-400 truncate">
                        {user.email}
                      </p>
                    </div>

                    {/* Status */}
                    <div className="flex items-center space-x-1">
                      <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                      <span className="text-xs text-green-400">Online</span>
                    </div>
                  </div>
                ))}
              </div>

              {/* Footer */}
              <div className="mt-3 pt-3 border-t border-gray-700">
                <p className="text-xs text-gray-500 text-center">
                  Real-time collaboration active
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Blinking styles */}
      <style jsx>{`
        @keyframes modernBlink {
          0%, 100% { 
            box-shadow: 0 0 0 0 rgba(59, 130, 246, 0.7);
            transform: scale(1);
          }
          50% { 
            box-shadow: 0 0 0 10px rgba(59, 130, 246, 0);
            transform: scale(1.05);
          }
        }
        
        .animate-modern-blink {
          animation: modernBlink 2s infinite;
        }
      `}</style>
    </div>
  );
};
