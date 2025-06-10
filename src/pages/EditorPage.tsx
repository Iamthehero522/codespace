//src/pages/EditorPage.tsx
import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { CodeEditor } from '../components/editor/CodeEditor';
import { EditorHeader } from '../components/editor/EditorHeader';
import { EditorSidebar } from '../components/editor/EditorSidebar';
import { OutputPanel } from '../components/editor/OutputPanel';
import { apiClient } from '../lib/api';
import { useAuth } from '../contexts/AuthContext';
import { useSocket } from '../hooks/useSocket';
import { useAutosave } from '../hooks/useAutosave';
import { DeleteConfirmationDialog } from '../components/editor/DeleteConfirmationDialog';
import { ShareTokenDialog } from '../components/share/ShareTokenDialog';

export const EditorPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const { user } = useAuth();
  const navigate = useNavigate();
  const [project, setProject] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [language, setLanguage] = useState('javascript');
  const [code, setCode] = useState('// Welcome to CodeSpace\nconsole.log("Hello, World!");');
  const [output, setOutput] = useState('');
  const [isRunning, setIsRunning] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [title, setTitle] = useState('Untitled Project');
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [showShareDialog, setShowShareDialog] = useState(false);
  const [currentShareId, setCurrentShareId] = useState('');
  const [currentShareTitle, setCurrentShareTitle] = useState('');
  const [showSidebar, setShowSidebar] = useState(true);
  const [showOutputPanel, setShowOutputPanel] = useState(true);
  const [hasUnsavedChanges, setHasUnsavedChanges] = useState(false);
  const [lastSavedAt, setLastSavedAt] = useState<Date | null>(null);
  const [ownerId, setOwnerId] = useState<string>('');
  
  const { activeUsers, emitDocumentChange, isConnected } = useSocket({
    documentId: id !== 'new' ? id : undefined,
    onDocumentChange: (data) => {
      console.log('📝 Received document change from user:', data.userId, data);
      
      // Only apply changes from other users
      if (data.userId !== user?.id) {
        if (data.content !== undefined && data.content !== code) {
          console.log('🔄 Updating code content from remote user');
          setCode(data.content);
          setProject(prev => ({ ...prev, content: data.content }));
        }
        
        if (data.title && data.title !== title) {
          console.log('🔄 Updating title from remote user');
          setTitle(data.title);
          setProject(prev => ({ ...prev, title: data.title }));
        }
      }
    },
    onActiveUsersUpdate: (users) => {
      console.log('👥 Active users updated in EditorPage:', users);
    },
    onUserJoined: (user) => {
      console.log('👋 User joined the document:', user);
    },
    onUserLeft: (userId) => {
      console.log('👋 User left the document:', userId);
    }
  });

  // Autosave functionality
  const { forceSave } = useAutosave({
    data: { title, content: code },
    onSave: async (data) => {
      if (id === 'new') return; // Don't autosave new documents
      
      setIsSaving(true);
      try {
        await apiClient.updateDocument(id!, data.title, data.content);
        setLastSavedAt(new Date());
        setHasUnsavedChanges(false);
        
        // Emit changes to other users
        emitDocumentChange({
          content: data.content,
          title: data.title,
          autoSave: true
        });
      } catch (error) {
        console.error('Autosave failed:', error);
      } finally {
        setIsSaving(false);
      }
    },
    delay: 3000, // Autosave after 3 seconds of inactivity
    enabled: id !== 'new' && hasUnsavedChanges,
  });

  useEffect(() => {
    if (id === 'new') {
      const newProject = {
        title: 'Untitled Project',
        content: code,
        owner_id: user?.id
      };
      setProject(newProject);
      setTitle('Untitled Project');
      setOwnerId(user?.id || '');
      setLoading(false);
    } else if (id && user) {
      fetchProject();
    }
  }, [id, user]);

  const fetchProject = async () => {
    try {
      const data = await apiClient.getDocument(id!);
      setProject(data);
      setCode(data.content || '');
      setTitle(data.title || 'Untitled Project');
      setOwnerId(data.owner_id || data.user_id || '');
      setLastSavedAt(data.updated_at ? new Date(data.updated_at) : null);
      
      // Detect language from filename
      const ext = data.title.split('.').pop()?.toLowerCase();
      if (ext) {
        const langMap: Record<string, string> = {
          'js': 'javascript',
          'ts': 'typescript',
          'py': 'python',
          'java': 'java',
          'cpp': 'cpp',
          'c': 'c'
        };
        setLanguage(langMap[ext] || 'javascript');
      }
      setHasUnsavedChanges(false);
    } catch (error) {
      console.error('Error fetching project:', error);
      navigate('/dashboard');
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async (newTitle: string, content: string) => {
    setIsSaving(true);
    try {
      if (id === 'new') {
        const data = await apiClient.createDocument(newTitle, content);
        setProject(data);
        setOwnerId(data.owner_id || data.user_id || user?.id || '');
        setLastSavedAt(new Date());
        navigate(`/editor/${data.id}`, { replace: true });
      } else {
        await apiClient.updateDocument(id!, newTitle, content);
        setProject(prev => ({ ...prev, title: newTitle, content }));
        setLastSavedAt(new Date());
        
        // Emit changes to other users
        emitDocumentChange({
          content: content,
          title: newTitle,
          manualSave: true
        });
      }
      setTitle(newTitle);
      setHasUnsavedChanges(false);
    } catch (error) {
      console.error('Error saving project:', error);
    } finally {
      setIsSaving(false);
    }
  };

  const handleTitleChange = (newTitle: string) => {
    setTitle(newTitle);
    setProject(prev => ({ ...prev, title: newTitle }));
    setHasUnsavedChanges(true);
  };

  const handleCodeChange = (newCode: string) => {
    console.log('📝 Code changed locally, emitting to other users');
    setCode(newCode);
    setProject(prev => ({ ...prev, content: newCode }));
    setHasUnsavedChanges(true);
    
    // Emit changes to other users with live editing flag
    if (id !== 'new' && isConnected) {
      emitDocumentChange({
        content: newCode,
        liveEdit: true
      });
    }
  };

  const handleRunCode = async (input?: string) => {
    setIsRunning(true);
    setOutput('Running...');
    
    try {
      const response = await apiClient.runCode(code, language, input);
      setOutput(response.output || response.error || 'No output');
    } catch (error) {
      setOutput(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setIsRunning(false);
    }
  };

  const handleDeleteProject = async () => {
    if (!id || id === 'new') {
      console.warn('Cannot delete unsaved or new project.');
      setShowDeleteConfirm(false);
      return;
    }

    setIsDeleting(true);
    try {
      await apiClient.deleteDocument(id);
      navigate('/dashboard');
    } catch (error) {
      console.error('Error deleting project:', error);
      setOutput(`Error deleting project: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setIsDeleting(false);
      setShowDeleteConfirm(false);
    }
  };

  const handleShareDocument = (docId: string, docTitle: string) => {
    setCurrentShareId(docId);
    setCurrentShareTitle(docTitle);
    setShowShareDialog(true);
  };
  
  const toggleSidebar = () => {
    setShowSidebar(prev => !prev);
  };

  const toggleOutputPanel = () => {
    setShowOutputPanel(prev => !prev);
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

  return (
    <div className="min-h-screen bg-gray-900 flex flex-col">
      <EditorHeader 
        project={{ title, content: code }}
        onSave={handleSave}
        onTitleChange={handleTitleChange}
        activeUsers={activeUsers}
        ownerId={ownerId}
        language={language}
        onLanguageChange={setLanguage}
        onRun={() => handleRunCode()}
        isRunning={isRunning}
        isSaving={isSaving}
        id={id!}
        onShare={handleShareDocument}
        onDeleteProject={() => setShowDeleteConfirm(true)}
        showSidebar={showSidebar}
        showOutputPanel={showOutputPanel}
        activeFileIsDirty={hasUnsavedChanges}
        onToggleSidebar={toggleSidebar}
        onToggleOutputPanel={toggleOutputPanel}
        isZipProject={false}
      />
      
      <div className="flex-1 flex">
        {showSidebar && <EditorSidebar />}
        
        <div className="flex-1 flex flex-col">
          <div className="flex-1">
            <CodeEditor
              value={code}
              onChange={handleCodeChange}
              language={language}
            />
          </div>
          
          {showOutputPanel && (
            <OutputPanel 
              output={output}
              isRunning={isRunning}
              onRunWithInput={handleRunCode}
              onClose={toggleOutputPanel}
            />
          )}
        </div>
      </div>

      {/* Status Bar */}
      <div className="bg-gray-800 border-t border-gray-700 px-4 py-2 flex items-center justify-between text-sm text-gray-400">
        <div className="flex items-center space-x-4">
          <span>Language: {language}</span>
          <span>Lines: {code.split('\n').length}</span>
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
          {hasUnsavedChanges && !isSaving && (
            <span className="flex items-center space-x-1 text-yellow-400">
              <div className="w-2 h-2 bg-yellow-400 rounded-full"></div>
              <span>Unsaved changes</span>
            </span>
          )}
          <span>Last saved: {formatLastSaved(lastSavedAt)}</span>
        </div>
      </div>

      {/* Delete Confirmation Dialog */}
      <DeleteConfirmationDialog
        isOpen={showDeleteConfirm}
        onClose={() => setShowDeleteConfirm(false)}
        onConfirm={handleDeleteProject}
        documentTitle={title}
        isDeleting={isDeleting}
      />

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
