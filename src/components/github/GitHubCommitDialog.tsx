import React, { useState } from 'react';
import { X, Github, Loader2, GitCommit, FileText } from 'lucide-react';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { apiClient } from '../../lib/api';

interface GitHubCommitDialogProps {
  isOpen: boolean;
  onClose: () => void;
  projectId: string;
  projectName: string;
  changedFiles: Array<{
    filePath: string;
    content: string;
    isDirty: boolean;
  }>;
}

export const GitHubCommitDialog: React.FC<GitHubCommitDialogProps> = ({
  isOpen,
  onClose,
  projectId,
  projectName,
  changedFiles,
}) => {
  const [commitMessage, setCommitMessage] = useState('');
  const [commitDescription, setCommitDescription] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);

  const handleCommit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!commitMessage.trim()) {
      setError('Commit message is required');
      return;
    }

    if (changedFiles.length === 0) {
      setError('No changes to commit');
      return;
    }

    setLoading(true);
    setError('');

    try {
      await apiClient.commitGitHubChanges({
        projectId,
        commitMessage: commitMessage.trim(),
        commitDescription: commitDescription.trim(),
        changedFiles: changedFiles.map(file => ({
          filePath: file.filePath,
          content: file.content,
        })),
      });

      setSuccess(true);
      setTimeout(() => {
        onClose();
        resetForm();
      }, 2000);
    } catch (err: any) {
      setError(err.message || 'Failed to commit changes to GitHub');
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setCommitMessage('');
    setCommitDescription('');
    setError('');
    setSuccess(false);
  };

  const handleClose = () => {
    if (!loading) {
      resetForm();
      onClose();
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg shadow-xl max-w-md w-full mx-4 border border-gray-700">
        <div className="flex items-center justify-between p-6 border-b border-gray-700">
          <div className="flex items-center space-x-3">
            <Github className="w-6 h-6 text-white" />
            <h3 className="text-lg font-semibold text-white">Commit Changes</h3>
          </div>
          <button
            onClick={handleClose}
            disabled={loading}
            className="text-gray-400 hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleCommit} className="p-6 space-y-6">
          {error && (
            <div className="bg-red-900/50 border border-red-500/50 rounded-lg p-4">
              <p className="text-sm text-red-300">{error}</p>
            </div>
          )}

          {success && (
            <div className="bg-green-900/50 border border-green-500/50 rounded-lg p-4">
              <p className="text-sm text-green-300">Changes committed successfully!</p>
            </div>
          )}

          {/* Project Info */}
          <div className="bg-gray-700 rounded-lg p-4">
            <h4 className="text-sm font-medium text-white mb-2">Project: {projectName}</h4>
            <div className="space-y-1">
              <p className="text-xs text-gray-400">Changed files ({changedFiles.length}):</p>
              {changedFiles.slice(0, 5).map((file, index) => (
                <div key={index} className="flex items-center space-x-2 text-xs text-gray-300">
                  <FileText className="w-3 h-3" />
                  <span>{file.filePath}</span>
                </div>
              ))}
              {changedFiles.length > 5 && (
                <p className="text-xs text-gray-400">...and {changedFiles.length - 5} more files</p>
              )}
            </div>
          </div>

          {/* Commit Message */}
          <Input
            label="Commit Message"
            value={commitMessage}
            onChange={(e) => setCommitMessage(e.target.value)}
            placeholder="Brief description of changes"
            icon={<GitCommit className="w-4 h-4" />}
            required
            maxLength={72}
          />

          {/* Commit Description */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Description (Optional)
            </label>
            <textarea
              value={commitDescription}
              onChange={(e) => setCommitDescription(e.target.value)}
              placeholder="Detailed description of changes..."
              rows={4}
              className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 placeholder-gray-400 text-white resize-none"
            />
          </div>

          {/* Commit Guidelines */}
          <div className="bg-blue-900/30 border border-blue-500/30 rounded-lg p-4">
            <p className="text-sm text-blue-300 mb-2">
              <strong>Commit Guidelines:</strong>
            </p>
            <ul className="text-xs text-blue-200 space-y-1 list-disc list-inside">
              <li>Use present tense ("Add feature" not "Added feature")</li>
              <li>Keep the first line under 72 characters</li>
              <li>Be descriptive but concise</li>
              <li>Reference issues if applicable (#123)</li>
            </ul>
          </div>

          <Button
            type="submit"
            disabled={loading || !commitMessage.trim() || changedFiles.length === 0}
            className="w-full"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                Committing...
              </>
            ) : (
              <>
                <GitCommit className="w-4 h-4 mr-2" />
                Commit to GitHub
              </>
            )}
          </Button>
        </form>
      </div>
    </div>
  );
};