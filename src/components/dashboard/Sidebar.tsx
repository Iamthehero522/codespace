import React, { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { 
  Code2, 
  Plus, 
  Folder, 
  Star, 
  Trash2, 
  Settings, 
  User,
  GitBranch,
  Terminal,
  Upload,
  Github,
  ChevronDown
} from 'lucide-react';
import { UploadZipDialog } from './UploadZipDialog';
import { GitHubImportDialog } from './GitHubImportDialog';

const menuItems = [
  { icon: Code2, label: 'Recent', path: '/dashboard' },
  { icon: Star, label: 'Starred', path: '/dashboard/starred' },
  { icon: Folder, label: 'My Projects', path: '/dashboard/projects' },
  { icon: GitBranch, label: 'Shared', path: '/dashboard/shared' },
  { icon: Trash2, label: 'Trash', path: '/dashboard/trash' },
];

interface SidebarProps {
  onProjectsUpdate?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ onProjectsUpdate }) => {
  const location = useLocation();
  const [showCreateMenu, setShowCreateMenu] = useState(false);
  const [showUploadDialog, setShowUploadDialog] = useState(false);
  const [showGitHubDialog, setShowGitHubDialog] = useState(false);

  const handleUploadSuccess = () => {
    onProjectsUpdate?.();
  };

  const handleGitHubImportSuccess = () => {
    onProjectsUpdate?.();
  };

  return (
    <>
      <div className="w-64 bg-gray-800 border-r border-gray-700 h-full flex flex-col">
        {/* Create Button with Dropdown */}
        <div className="p-4">
          <div className="relative">
            <button
              onClick={() => setShowCreateMenu(!showCreateMenu)}
              className="w-full bg-blue-600 hover:bg-blue-700 text-white px-4 py-3 rounded-lg flex items-center justify-between transition-colors duration-200 shadow-sm hover:shadow-md"
            >
              <div className="flex items-center space-x-3">
                <Plus className="w-5 h-5" />
                <span>New Project</span>
              </div>
              <ChevronDown className={`w-4 h-4 transition-transform ${showCreateMenu ? 'rotate-180' : ''}`} />
            </button>

            {showCreateMenu && (
              <div className="absolute top-full left-0 right-0 mt-2 bg-gray-800 rounded-lg shadow-lg border border-gray-700 z-10">
                <Link
                  to="/editor/new"
                  onClick={() => setShowCreateMenu(false)}
                  className="flex items-center space-x-3 px-4 py-3 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors rounded-t-lg"
                >
                  <Code2 className="w-4 h-4" />
                  <span>Code Editor</span>
                </Link>
                <button
                  onClick={() => {
                    setShowCreateMenu(false);
                    setShowUploadDialog(true);
                  }}
                  className="w-full flex items-center space-x-3 px-4 py-3 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors"
                >
                  <Upload className="w-4 h-4" />
                  <span>Upload ZIP File</span>
                </button>
                <button
                  onClick={() => {
                    setShowCreateMenu(false);
                    setShowGitHubDialog(true);
                  }}
                  className="w-full flex items-center space-x-3 px-4 py-3 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors rounded-b-lg"
                >
                  <Github className="w-4 h-4" />
                  <span>GitHub Import</span>
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-4">
          <ul className="space-y-1">
            {menuItems.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.path;
              
              return (
                <li key={item.path}>
                  <Link
                    to={item.path}
                    className={`
                      flex items-center space-x-3 px-3 py-2 rounded-lg transition-colors duration-200
                      ${isActive 
                        ? 'bg-blue-600 text-white' 
                        : 'text-gray-300 hover:bg-gray-700 hover:text-white'
                      }
                    `}
                  >
                    <Icon className="w-5 h-5" />
                    <span>{item.label}</span>
                  </Link>
                </li>
              );
            })}
          </ul>
        </nav>

        {/* Bottom Navigation */}
        <div className="p-4 border-t border-gray-700">
          <ul className="space-y-1">
            <li>
              <Link
                to="/dashboard/profile"
                className="flex items-center space-x-3 px-3 py-2 text-gray-300 hover:bg-gray-700 hover:text-white rounded-lg transition-colors duration-200"
              >
                <User className="w-5 h-5" />
                <span>Profile</span>
              </Link>
            </li>
            <li>
              <Link
                to="/dashboard/settings"
                className="flex items-center space-x-3 px-3 py-2 text-gray-300 hover:bg-gray-700 hover:text-white rounded-lg transition-colors duration-200"
              >
                <Settings className="w-5 h-5" />
                <span>Settings</span>
              </Link>
            </li>
          </ul>
        </div>
      </div>

      {/* Upload ZIP Dialog */}
      <UploadZipDialog
        isOpen={showUploadDialog}
        onClose={() => setShowUploadDialog(false)}
        onUploadSuccess={handleUploadSuccess}
      />

      {/* GitHub Import Dialog */}
      <GitHubImportDialog
        isOpen={showGitHubDialog}
        onClose={() => setShowGitHubDialog(false)}
        onImportSuccess={handleGitHubImportSuccess}
      />
    </>
  );
};