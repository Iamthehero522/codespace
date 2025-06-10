import React from 'react';
import { User, Crown } from 'lucide-react';

interface ActiveUser {
  id: string;
  email: string;
  name: string;
  avatarUrl?: string;
  isOwner?: boolean;
}

interface ActiveUsersProps {
  users: ActiveUser[];
  ownerId?: string;
}

export const ActiveUsers: React.FC<ActiveUsersProps> = ({ users, ownerId }) => {
  if (users.length === 0) return null;

  const usersWithOwnership = users.map(user => ({
    ...user,
    isOwner: user.id === ownerId
  }));

  const getInitials = (name: string) => {
    return name
      .split(' ')
      .map(word => word.charAt(0))
      .join('')
      .toUpperCase()
      .slice(0, 2);
  };

  const getAvatarColor = (userId: string) => {
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
    const index = userId.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0);
    return colors[index % colors.length];
  };

  return (
    <div className="flex items-center space-x-2">
      <span className="text-sm text-gray-400">Active:</span>
      <div className="flex -space-x-2">
        {usersWithOwnership.slice(0, 5).map((user) => (
          <div
            key={user.id}
            className="relative group"
            title={`${user.name} ${user.isOwner ? '(Owner)' : ''}`}
          >
            {user.avatarUrl ? (
              <img
                src={user.avatarUrl}
                alt={user.name}
                className="w-8 h-8 rounded-full border-2 border-gray-800 shadow-sm"
              />
            ) : (
              <div className={`
                w-8 h-8 rounded-full border-2 border-gray-800 shadow-sm flex items-center justify-center text-xs font-medium text-white
                ${getAvatarColor(user.id)}
              `}>
                {getInitials(user.name)}
              </div>
            )}
            <div className="absolute bottom-0 right-0 w-3 h-3 bg-green-400 border-2 border-gray-800 rounded-full"></div>
            {user.isOwner && (
              <div className="absolute -top-1 -right-1 w-4 h-4 bg-yellow-400 border border-gray-800 rounded-full flex items-center justify-center">
                <Crown className="w-2 h-2 text-gray-800" />
              </div>
            )}
          </div>
        ))}
        {users.length > 5 && (
          <div className="w-8 h-8 rounded-full border-2 border-gray-800 shadow-sm bg-gray-700 flex items-center justify-center text-xs font-medium text-gray-300">
            +{users.length - 5}
          </div>
        )}
      </div>
    </div>
  );
};