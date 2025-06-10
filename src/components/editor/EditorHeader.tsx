//src/components/editor/EditorHeader.tsx
import React, { useState } from 'react';
import { 
  Save, 
  Share, 
  Play, 
  Settings, 
  Eye,
  LayoutDashboard,
  Terminal,
  ChevronDown,
  Loader2,
  Trash2,
  Edit2,
  Github,
  GitCommit
} from 'lucide-react';
import { TeamButton } from '../collaboration/TeamButton';

interface EditorHeaderProps {
  project?: {
    title: string;
    content: string;
  };
  onSave?: (title: string, content: string) => void;
  onTitleChange?: (title: string) => void;
  activeUsers: any[];
  ownerId?: string;
  language: string;
  onLanguageChange: (language: string) => void;
  onRun: () => void;
  isRunning: boolean;
  isSaving?: boolean;
  id: string;
  onShare?: (id: string, title: string) => void;
  onDeleteProject: () => void;
  showSidebar: boolean;
  showOutputPanel: boolean;
  activeFileIsDirty: boolean;
  onToggleSidebar: () => void;
  onToggleOutputPanel: () => void;
  isZipProject?: boolean;
  isGitHubProject?: boolean;
  onCommitChanges?: () => void;
}

const languages = [
  { id: 'javascript', name: 'JavaScript', ext: '.js' },
  { id: 'typescript', name: 'TypeScript', ext: '.ts' },
  { id: 'python', name: 'Python', ext: '.py' },
  { id: 'java', name: 'Java', ext: '.java' },
  { id: 'cpp', name: 'C++', ext: '.cpp' },
  { id: 'c', name: 'C', ext: '.c' },
];

export const EditorHeader: React.FC<EditorHeaderProps> = ({
  project,
  onSave,
  onTitleChange,
  activeUsers,
  ownerId,
  language,
  onLanguageChange,
  onRun,
  isRunning,
  isSaving = false,
  id,
  onShare,
  onDeleteProject,
  showSidebar,
  showOutputPanel,
  activeFileIsDirty,
  onToggleSidebar,
  onToggleOutputPanel,
  isZipProject = false,
  isGitHubProject = false,
  onCommitChanges,
}) => {
  const [title, setTitle] = useState(project?.title || 'Untitled Project');
  const [isEditingTitle, setIsEditingTitle] = useState(false);
  const [showLanguageDropdown, setShowLanguageDropdown] = useState(false);
  const [showViewDropdown, setShowViewDropdown] = useState(false);
  const [showSettingsDropdown, setShowSettingsDropdown] = useState(false);

  const handleTitleChange = (newTitle: string) => {
    setTitle(newTitle);
    onTitleChange?.(newTitle);
  };

  const handleTitleSubmit = () => {
    setIsEditingTitle(false);
    if (onSave && project) {
      onSave(title, project.content);
    }
  };

  const handleTitleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleTitleSubmit();
    } else if (e.key === 'Escape') {
      setTitle(project?.title || 'Untitled Project');
      setIsEditingTitle(false);
    }
  };

  const handleSave = () => {
    if (onSave && project) {
      onSave(title, project.content);
    }
  };

  const handleShare = () => {
    if (onShare && id && id !== 'new') {
      onShare(id, title);
    }
  };

  const currentLanguage = languages.find(lang => lang.id === language) || languages[0];
  const shouldBlink = activeUsers.length > 0;

  return (
    <header className="bg-gray-800 border-b border-gray-700 px-6 py-3">
      <div className="flex items-center justify-between">
        {/* Left Section */}
        <div className="flex items-center space-x-4">
          {/* Title with Edit Functionality */}
          <div className="flex items-center space-x-2">
            {isEditingTitle ? (
              <input
                type="text"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                onBlur={handleTitleSubmit}
                onKeyDown={handleTitleKeyPress}
                className="text-lg font-semibold text-white bg-gray-700 border border-gray-600 rounded px-2 py-1 focus:outline-none focus:ring-2 focus:ring-blue-500"
                autoFocus
                disabled={isZipProject || isGitHubProject}
              />
            ) : (
              <div className="flex items-center space-x-2">
                <span className="text-lg font-semibold text-white">
                  {title}
                </span>
                {!isZipProject && !isGitHubProject && (
                  <button
                    onClick={() => setIsEditingTitle(true)}
                    className="p-1 text-gray-400 hover:text-white rounded transition-colors"
                    title="Rename project"
                  >
                    <Edit2 className="w-4 h-4" />
                  </button>
                )}
                {isGitHubProject && (
                  <Github className="w-4 h-4 text-gray-400" title="GitHub Project" />
                )}
              </div>
            )}
          </div>
          
          {/* Language Selector - Only for code projects */}
          {!isZipProject && !isGitHubProject && (
            <div className="relative">
              <button
                onClick={() => setShowLanguageDropdown(!showLanguageDropdown)}
                className="flex items-center space-x-2 px-3 py-1 bg-gray-700 rounded-lg hover:bg-gray-600 transition-colors"
              >
                <span className="text-sm text-gray-300">{currentLanguage?.name || language}</span>
                <ChevronDown className="w-4 h-4 text-gray-400" />
              </button>
              
              {showLanguageDropdown && (
                <div className="absolute top-full left-0 mt-1 w-48 bg-gray-800 rounded-lg shadow-lg border border-gray-700 z-10">
                  {languages.map((lang) => (
                    <button
                      key={lang.id}
                      onClick={() => {
                        onLanguageChange(lang.id);
                        setShowLanguageDropdown(false);
                      }}
                      className={`w-full text-left px-3 py-2 text-sm hover:bg-gray-700 first:rounded-t-lg last:rounded-b-lg ${
                        lang.id === language ? 'text-blue-400' : 'text-gray-300'
                      }`}
                    >
                      {lang.name} ({lang.ext})
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right Section */}
        <div className="flex items-center space-x-3">
          {/* GitHub Commit Button - Only for GitHub projects */}
          {isGitHubProject && onCommitChanges && (
            <button
              onClick={onCommitChanges}
              className="flex items-center space-x-2 px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg transition-colors"
              title="Commit changes to GitHub (Ctrl+Shift+G)"
            >
              <GitCommit className="w-4 h-4" />
              <span>Commit</span>
            </button>
          )}

          {/* Run Button - Only for code projects */}
          {!isZipProject && (
            <button
              onClick={onRun}
              disabled={isRunning}
              className="flex items-center space-x-2 px-4 py-2 bg-green-600 hover:bg-green-700 disabled:bg-green-800 text-white rounded-lg transition-colors"
            >
              {isRunning ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Play className="w-4 h-4" />
              )}
              <span>{isRunning ? 'Running...' : 'Run'}</span>
            </button>
          )}
          
          {/* Save Button */}
          <button
            onClick={handleSave}
            disabled={isSaving || (!activeFileIsDirty && !isZipProject && !isGitHubProject)}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-colors ${
              (activeFileIsDirty || isZipProject || isGitHubProject) && !isSaving
                ? 'bg-blue-600 hover:bg-blue-700 text-white' 
                : 'bg-gray-700 text-gray-400 cursor-not-allowed'
            }`}
          >
            {isSaving ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Save className="w-4 h-4" />
            )}
            <span>
              {isSaving 
                ? 'Saving...' 
                : (isZipProject || isGitHubProject)
                  ? 'Save' 
                  : activeFileIsDirty 
                    ? 'Save' 
                    : 'Saved'
              }
            </span>
          </button>
          
          {/* Share Button */}
          <button
            onClick={handleShare}
            disabled={!onShare || id === 'new'}
            className="flex items-center space-x-2 px-4 py-2 border border-gray-600 hover:border-gray-500 text-gray-300 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Share className="w-4 h-4" />
            <span>Share</span>
          </button>

          {/* Team Button */}
          <TeamButton 
            activeUsers={activeUsers} 
            ownerId={ownerId}
            isBlinking={shouldBlink}
          />

          {/* View Dropdown */}
          <div className="relative">
            <button
              onClick={() => setShowViewDropdown(!showViewDropdown)}
              className="p-2 text-gray-400 hover:text-white hover:bg-gray-700 rounded-lg transition-colors"
              title="View Options"
            >
              <Eye className="w-5 h-5" />
            </button>
            
            {showViewDropdown && (
              <div className="absolute top-full right-0 mt-1 w-48 bg-gray-800 rounded-lg shadow-lg border border-gray-700 z-10">
                <button
                  onClick={() => {
                    onToggleSidebar();
                    setShowViewDropdown(false);
                  }}
                  className="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 flex items-center space-x-2 rounded-t-lg"
                >
                  <LayoutDashboard className="w-4 h-4" />
                  <span>{showSidebar ? 'Hide Sidebar' : 'Show Sidebar'}</span>
                </button>
                <button
                  onClick={() => {
                    onToggleOutputPanel();
                    setShowViewDropdown(false);
                  }}
                  className="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 flex items-center space-x-2 rounded-b-lg"
                >
                  <Terminal className="w-4 h-4" />
                  <span>{showOutputPanel ? 'Hide Terminal' : 'Show Terminal'}</span>
                </button>
              </div>
            )}
          </div>

          {/* Settings Dropdown */}
          <div className="relative">
            <button
              onClick={() => setShowSettingsDropdown(!showSettingsDropdown)}
              className="p-2 text-gray-400 hover:text-white hover:bg-gray-700 rounded-lg transition-colors"
              title="Settings"
            >
              <Settings className="w-5 h-5" />
            </button>
            
            {showSettingsDropdown && (
              <div className="absolute top-full right-0 mt-1 w-48 bg-gray-800 rounded-lg shadow-lg border border-gray-700 z-10">
                <button
                  onClick={() => {
                    onDeleteProject();
                    setShowSettingsDropdown(false);
                  }}
                  className="w-full text-left px-3 py-2 text-sm text-red-400 hover:bg-gray-700 flex items-center space-x-2 rounded-lg"
                >
                  <Trash2 className="w-4 h-4" />
                  <span>Delete Project</span>
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};