import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { CodeEditor } from '../components/editor/CodeEditor';
import { EditorHeader } from '../components/editor/EditorHeader';
import { ProjectFileSidebar } from '../components/editor/ProjectFileSidebar';
import { OutputPanel } from '../components/editor/OutputPanel';
import { FileTabs } from '../components/editor/FileTabs';
import { ShareTokenDialog } from '../components/share/ShareTokenDialog';
import { apiClient } from '../lib/api';
import { useAuth } from '../contexts/AuthContext';
import { useSocket } from '../hooks/useSocket';
import { useAutosave } from '../hooks/useAutosave';

interface ProjectFile {
  id: string;
  relative_path: string;
  is_directory: boolean;
  size?: number;
  mime_type?: string;
}

interface OpenFile {
  filePath: string;
  content: string;
  language: string;
  isDirty: boolean;
}

interface Project {
  id: string;
  name: string;
  description?: string;
  status: string;
  files: ProjectFile[];
  updated_at?: string;
  owner_id?: string;
  user_id?: string;
}

export const ProjectPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const { user } = useAuth();
  const navigate = useNavigate();
  const [project, setProject] = useState<Project | null>(null);
  const [loading, setLoading] = useState(true);
  const [openFiles, setOpenFiles] = useState<OpenFile[]>([]);
  const [activeFilePath, setActiveFilePath] = useState<string>('');
  const [output, setOutput] = useState('');
  const [isRunning, setIsRunning] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [showSidebar, setShowSidebar] = useState(true);
  const [showOutputPanel, setShowOutputPanel] = useState(true);
  const [showShareDialog, setShowShareDialog] = useState(false);
  const [currentShareId, setCurrentShareId] = useState('');
  const [currentShareTitle, setCurrentShareTitle] = useState('');
  const [lastSavedAt, setLastSavedAt] = useState<Date | null>(null);
  const [ownerId, setOwnerId] = useState<string>('');

  const { activeUsers, emitDocumentChange, isConnected } = useSocket({
    documentId: id,
    onDocumentChange: (data) => {
      console.log('📝 Received file change from user:', data.userId, data);
      
      // Only apply changes from other users
      if (data.userId !== user?.id && data.filePath && data.content !== undefined) {
        console.log('🔄 Updating file content from remote user:', data.filePath);
        setOpenFiles(prev =>
          prev.map(file =>
            file.filePath === data.filePath 
              ? { ...file, content: data.content, isDirty: false }
              : file
          )
        );
      }
    },
    onActiveUsersUpdate: (users) => {
      console.log('👥 Active users updated in ProjectPage:', users);
    },
    onUserJoined: (user) => {
      console.log('👋 User joined the project:', user);
    },
    onUserLeft: (userId) => {
      console.log('👋 User left the project:', userId);
    }
  });

  const activeFile = openFiles.find(f => f.filePath === activeFilePath);

  // Autosave functionality for the active file
  const { forceSave } = useAutosave({
    data: { filePath: activeFilePath, content: activeFile?.content || '' },
    onSave: async (data) => {
      if (!data.filePath || !activeFile?.isDirty) return;
      
      setIsSaving(true);
      try {
        await apiClient.updateProjectFile(id!, data.filePath, data.content);
        setOpenFiles(prev =>
          prev.map(file =>
            file.filePath === data.filePath ? { ...file, isDirty: false } : file
          )
        );
        setLastSavedAt(new Date());
        
        // Emit changes to other users
        emitDocumentChange({
          filePath: data.filePath,
          content: data.content,
          autoSave: true
        });
      } catch (error) {
        console.error('Autosave failed:', error);
      } finally {
        setIsSaving(false);
      }
    },
    delay: 3000, // Autosave after 3 seconds of inactivity
    enabled: activeFile?.isDirty || false,
  });

  useEffect(() => {
    if (id && user) {
      fetchProject();
    }
  }, [id, user]);

  // Add keyboard shortcut for save (Ctrl+S)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.key === 's') {
        e.preventDefault();
        handleSave();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [activeFilePath, openFiles]);

  const fetchProject = async () => {
    try {
      const data = await apiClient.getProject(id!);
      setProject(data);
      setOwnerId(data.owner_id || data.user_id || '');
      setLastSavedAt(data.updated_at ? new Date(data.updated_at) : null);
      
      // Auto-select first non-directory file
      const firstFile = data.files.find((file: ProjectFile) => !file.is_directory);
      if (firstFile) {
        await openFileInTab(firstFile.relative_path);
      }
    } catch (error) {
      console.error('Error fetching project:', error);
      navigate('/dashboard');
    } finally {
      setLoading(false);
    }
  };

  const getLanguageFromPath = (filePath: string): string => {
    const ext = filePath.split('.').pop()?.toLowerCase();
    if (ext) {
      const langMap: Record<string, string> = {
        'js': 'javascript',
        'jsx': 'javascript',
        'ts': 'typescript',
        'tsx': 'typescript',
        'py': 'python',
        'java': 'java',
        'cpp': 'cpp',
        'c': 'c',
        'html': 'html',
        'css': 'css',
        'json': 'json',
        'md': 'markdown',
        'xml': 'xml',
        'yml': 'yaml',
        'yaml': 'yaml',
        'sh': 'shell',
        'sql': 'sql',
        'php': 'php',
        'rb': 'ruby',
        'go': 'go',
        'rs': 'rust',
        'kt': 'kotlin',
        'swift': 'swift'
      };
      return langMap[ext] || 'text';
    }
    return 'text';
  };

  const openFileInTab = async (filePath: string) => {
    setActiveFilePath(filePath);
    const existingFile = openFiles.find(f => f.filePath === filePath);

    if (!existingFile) {
      try {
        const response = await apiClient.getProjectFile(id!, filePath);
        const newFile: OpenFile = {
          filePath,
          content: response.content,
          language: getLanguageFromPath(filePath),
          isDirty: false,
        };
        setOpenFiles(prev => [...prev, newFile]);
      } catch (error) {
        console.error('Error opening file in tab:', error);
        setOutput(`Error loading file: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }
  };

  const handleTabClick = (filePath: string) => {
    setActiveFilePath(filePath);
  };

  const handleCloseTab = (filePathToClose: string) => {
    const fileToClose = openFiles.find(f => f.filePath === filePathToClose);
    
    if (fileToClose?.isDirty) {
      const confirmClose = window.confirm(`File "${filePathToClose.split('/').pop()}" has unsaved changes. Close anyway?`);
      if (!confirmClose) {
        return;
      }
    }

    setOpenFiles(prev => prev.filter(file => file.filePath !== filePathToClose));
    
    if (activeFilePath === filePathToClose) {
      const remainingFiles = openFiles.filter(file => file.filePath !== filePathToClose);
      if (remainingFiles.length > 0) {
        setActiveFilePath(remainingFiles[0].filePath);
      } else {
        setActiveFilePath('');
      }
    }
  };

  const handleSave = async () => {
    const activeFile = openFiles.find(f => f.filePath === activeFilePath);
    if (!activeFile || !activeFile.isDirty) return;
    
    setIsSaving(true);
    try {
      await apiClient.updateProjectFile(id!, activeFile.filePath, activeFile.content);
      setOpenFiles(prev =>
        prev.map(file =>
          file.filePath === activeFile.filePath ? { ...file, isDirty: false } : file
        )
      );
      setLastSavedAt(new Date());
      setOutput(`File "${activeFile.filePath.split('/').pop()}" saved successfully.`);
      
      // Emit changes to other users
      emitDocumentChange({
        filePath: activeFile.filePath,
        content: activeFile.content,
        manualSave: true
      });
    } catch (error) {
      console.error('Error saving file:', error);
      setOutput(`Error saving file: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setIsSaving(false);
    }
  };

  const handleCodeChange = (newCode: string) => {
    console.log('📝 File content changed locally, emitting to other users');
    setOpenFiles(prev =>
      prev.map(file =>
        file.filePath === activeFilePath ? { ...file, content: newCode, isDirty: true } : file
      )
    );
    
    // Emit changes to other users with live editing flag
    if (activeFilePath && isConnected) {
      emitDocumentChange({
        filePath: activeFilePath,
        content: newCode,
        liveEdit: true
      });
    }
  };

  const handleRunCode = async (input?: string) => {
    const activeFile = openFiles.find(f => f.filePath === activeFilePath);
    if (!activeFile) return;
    
    setIsRunning(true);
    setOutput('Running...');
    
    try {
      const response = await apiClient.runCode(activeFile.content, activeFile.language, input);
      setOutput(response.output || response.error || 'No output');
    } catch (error) {
      setOutput(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setIsRunning(false);
    }
  };

  const handleDeleteProject = async () => {
    if (!id) return;
    
    const confirmDelete = window.confirm(`Are you sure you want to delete project "${project?.name}"? This action cannot be undone.`);
    if (!confirmDelete) return;
    
    try {
      await apiClient.deleteProject(id);
      navigate('/dashboard');
    } catch (error) {
      console.error('Error deleting project:', error);
      setOutput(`Error deleting project: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  };

  const handleShareDocument = (docId: string, docTitle: string) => {
    setCurrentShareId(docId);
    setCurrentShareTitle(docTitle);
    setShowShareDialog(true);
  };

  const formatLastSaved = (date: Date | null) => {
    if (!date) return 'Never saved';
    
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffSeconds = Math.floor(diffMs / 1000);
    const diffMinutes = Math.floor(diffSeconds / 60);
    const diffHours = Math.floor(diffMinutes / 60);
    
    if (diffSeconds < 60) {
      return 'Just now';
    } else if (diffMinutes < 60) {
      return `${diffMinutes} minute${diffMinutes !== 1 ? 's' : ''} ago`;
    } else if (diffHours < 24) {
      return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`;
    } else {
      return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="flex flex-col items-center space-y-4">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
          <p className="text-gray-400">Loading project...</p>
        </div>
      </div>
    );
  }

  if (!project) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <h2 className="text-xl font-semibold text-white mb-2">Project not found</h2>
          <p className="text-gray-400">The project you're looking for doesn't exist or you don't have access to it.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 flex flex-col">
      <EditorHeader 
        project={{ title: project.name, content: activeFile?.content || '' }}
        onSave={handleSave}
        onTitleChange={() => {}} // Project name editing not implemented for ZIP projects
        activeUsers={activeUsers}
        ownerId={ownerId}
        language={activeFile?.language || 'text'}
        onLanguageChange={() => {}} // Language change per file not implemented for ZIP projects
        onRun={() => handleRunCode()}
        isRunning={isRunning}
        isSaving={isSaving}
        id={id!}
        onShare={handleShareDocument}
        onDeleteProject={handleDeleteProject}
        showSidebar={showSidebar}
        showOutputPanel={showOutputPanel}
        onToggleSidebar={() => setShowSidebar(prev => !prev)}
        onToggleOutputPanel={() => setShowOutputPanel(prev => !prev)}
        activeFileIsDirty={activeFile?.isDirty || false}
        isZipProject={true}
      />
      
      <div className="flex-1 flex">
        {showSidebar && (
          <ProjectFileSidebar
            projectId={id!}
            files={project.files}
            onOpenFileInTab={openFileInTab}
            selectedFile={activeFilePath}
          />
        )}
        
        <div className="flex-1 flex flex-col">
          <FileTabs
            openFiles={openFiles}
            activeFilePath={activeFilePath}
            onTabClick={handleTabClick}
            onCloseTab={handleCloseTab}
          />
          
          <div className="flex-1">
            {activeFilePath ? (
              <CodeEditor
                value={activeFile?.content || ''}
                onChange={handleCodeChange}
                language={activeFile?.language || 'text'}
              />
            ) : (
              <div className="h-full flex items-center justify-center bg-gray-900">
                <div className="text-center">
                  <h3 className="text-lg font-medium text-white mb-2">Select a file to edit</h3>
                  <p className="text-gray-400">Choose a file from the sidebar to start editing</p>
                </div>
              </div>
            )}
          </div>
          
          {showOutputPanel && (
            <OutputPanel 
              output={output}
              isRunning={isRunning}
              onRunWithInput={handleRunCode}
              onClose={() => setShowOutputPanel(false)}
            />
          )}
        </div>
      </div>

      {/* Status Bar */}
      <div className="bg-gray-800 border-t border-gray-700 px-4 py-2 flex items-center justify-between text-sm text-gray-400">
        <div className="flex items-center space-x-4">
          <span>Project: {project.name}</span>
          {activeFile && <span>File: {activeFile.filePath.split('/').pop()}</span>}
          {activeFile && <span>Language: {activeFile.language}</span>}
          <span>Active Users: {activeUsers.length}</span>
          <span className={`flex items-center space-x-1 ${isConnected ? 'text-green-400' : 'text-red-400'}`}>
            <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-400' : 'bg-red-400'}`}></div>
            <span>{isConnected ? 'Connected' : 'Disconnected'}</span>
          </span>
        </div>
        <div className="flex items-center space-x-4">
          {isSaving && (
            <span className="flex items-center space-x-1 text-blue-400">
              <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse"></div>
              <span>Saving...</span>
            </span>
          )}
          {activeFile?.isDirty && !isSaving && (
            <span className="flex items-center space-x-1 text-yellow-400">
              <div className="w-2 h-2 bg-yellow-400 rounded-full"></div>
              <span>Unsaved changes</span>
            </span>
          )}
          <span>Last saved: {formatLastSaved(lastSavedAt)}</span>
        </div>
      </div>

      {/* Share Dialog */}
      <ShareTokenDialog
        isOpen={showShareDialog}
        onClose={() => setShowShareDialog(false)}
        fileId={currentShareId}
        fileName={currentShareTitle}
      />
    </div>
  );
};
