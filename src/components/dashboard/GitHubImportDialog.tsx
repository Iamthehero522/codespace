import React, { useState } from 'react';
import { X, Github, Loader2, Search, GitBranch, Star, Eye } from 'lucide-react';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { apiClient } from '../../lib/api';

interface GitHubRepo {
  id: number;
  name: string;
  full_name: string;
  description: string;
  private: boolean;
  stargazers_count: number;
  language: string;
  updated_at: string;
  clone_url: string;
  default_branch: string;
}

interface GitHubImportDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onImportSuccess: () => void;
}

export const GitHubImportDialog: React.FC<GitHubImportDialogProps> = ({
  isOpen,
  onClose,
  onImportSuccess,
}) => {
  const [step, setStep] = useState<'auth' | 'repos' | 'importing'>('auth');
  const [repositories, setRepositories] = useState<GitHubRepo[]>([]);
  const [selectedRepo, setSelectedRepo] = useState<GitHubRepo | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [githubToken, setGithubToken] = useState('');

  const handleGitHubAuth = async () => {
    if (!githubToken.trim()) {
      setError('Please enter your GitHub personal access token');
      return;
    }

    setLoading(true);
    setError('');

    try {
      const repos = await apiClient.getGitHubRepositories(githubToken);
      setRepositories(repos);
      setStep('repos');
    } catch (err: any) {
      setError(err.message || 'Failed to fetch repositories. Please check your token.');
    } finally {
      setLoading(false);
    }
  };

  const handleImportRepository = async () => {
    if (!selectedRepo || !githubToken) return;

    setStep('importing');
    setLoading(true);
    setError('');

    try {
      await apiClient.importGitHubRepository({
        repoUrl: selectedRepo.clone_url,
        repoName: selectedRepo.name,
        description: selectedRepo.description,
        githubToken: githubToken,
        defaultBranch: selectedRepo.default_branch,
      });

      onImportSuccess();
      onClose();
      resetState();
    } catch (err: any) {
      setError(err.message || 'Failed to import repository');
      setStep('repos');
    } finally {
      setLoading(false);
    }
  };

  const resetState = () => {
    setStep('auth');
    setRepositories([]);
    setSelectedRepo(null);
    setSearchQuery('');
    setError('');
    setGithubToken('');
  };

  const handleClose = () => {
    if (!loading) {
      resetState();
      onClose();
    }
  };

  const filteredRepos = repositories.filter(repo =>
    repo.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    repo.description?.toLowerCase().includes(searchQuery.toLowerCase())
  );

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg shadow-xl max-w-2xl w-full mx-4 border border-gray-700 max-h-[90vh] overflow-hidden">
        <div className="flex items-center justify-between p-6 border-b border-gray-700">
          <div className="flex items-center space-x-3">
            <Github className="w-6 h-6 text-white" />
            <h3 className="text-lg font-semibold text-white">Import from GitHub</h3>
          </div>
          <button
            onClick={handleClose}
            disabled={loading}
            className="text-gray-400 hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6">
          {error && (
            <div className="bg-red-900/50 border border-red-500/50 rounded-lg p-4 mb-6">
              <p className="text-sm text-red-300">{error}</p>
            </div>
          )}

          {step === 'auth' && (
            <div className="space-y-6">
              <div className="text-center">
                <Github className="w-16 h-16 text-gray-400 mx-auto mb-4" />
                <h4 className="text-xl font-semibold text-white mb-2">Connect to GitHub</h4>
                <p className="text-gray-400">
                  Enter your GitHub personal access token to import repositories
                </p>
              </div>

              <div className="space-y-4">
                <Input
                  type="password"
                  label="GitHub Personal Access Token"
                  value={githubToken}
                  onChange={(e) => setGithubToken(e.target.value)}
                  placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
                  icon={<Github className="w-4 h-4" />}
                  required
                />
                
                <div className="bg-blue-900/30 border border-blue-500/30 rounded-lg p-4">
                  <p className="text-sm text-blue-300 mb-2">
                    <strong>How to get a GitHub token:</strong>
                  </p>
                  <ol className="text-xs text-blue-200 space-y-1 list-decimal list-inside">
                    <li>Go to GitHub Settings → Developer settings → Personal access tokens</li>
                    <li>Click "Generate new token (classic)"</li>
                    <li>Select scopes: <code>repo</code>, <code>read:user</code></li>
                    <li>Copy the generated token and paste it here</li>
                  </ol>
                </div>
              </div>

              <Button
                onClick={handleGitHubAuth}
                disabled={loading || !githubToken.trim()}
                className="w-full"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Connecting...
                  </>
                ) : (
                  <>
                    <Github className="w-4 h-4 mr-2" />
                    Connect to GitHub
                  </>
                )}
              </Button>
            </div>
          )}

          {step === 'repos' && (
            <div className="space-y-6">
              <div>
                <h4 className="text-lg font-semibold text-white mb-2">Select Repository</h4>
                <p className="text-gray-400 mb-4">Choose a repository to import into CodeSpace</p>
                
                <div className="relative mb-4">
                  <Search className="w-4 h-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                  <input
                    type="text"
                    placeholder="Search repositories..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full pl-10 pr-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-white placeholder-gray-400"
                  />
                </div>
              </div>

              <div className="max-h-96 overflow-y-auto space-y-2">
                {filteredRepos.length === 0 ? (
                  <div className="text-center py-8">
                    <Github className="w-12 h-12 text-gray-600 mx-auto mb-4" />
                    <p className="text-gray-400">No repositories found</p>
                  </div>
                ) : (
                  filteredRepos.map((repo) => (
                    <div
                      key={repo.id}
                      className={`p-4 border rounded-lg cursor-pointer transition-all ${
                        selectedRepo?.id === repo.id
                          ? 'border-blue-500 bg-blue-900/20'
                          : 'border-gray-600 hover:border-gray-500 hover:bg-gray-700/50'
                      }`}
                      onClick={() => setSelectedRepo(repo)}
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center space-x-2 mb-1">
                            <h5 className="font-medium text-white">{repo.name}</h5>
                            {repo.private && (
                              <span className="px-2 py-1 text-xs bg-yellow-600 text-yellow-100 rounded">
                                Private
                              </span>
                            )}
                          </div>
                          
                          {repo.description && (
                            <p className="text-sm text-gray-400 mb-2">{repo.description}</p>
                          )}
                          
                          <div className="flex items-center space-x-4 text-xs text-gray-500">
                            {repo.language && (
                              <span className="flex items-center space-x-1">
                                <div className="w-2 h-2 bg-blue-400 rounded-full"></div>
                                <span>{repo.language}</span>
                              </span>
                            )}
                            <span className="flex items-center space-x-1">
                              <Star className="w-3 h-3" />
                              <span>{repo.stargazers_count}</span>
                            </span>
                            <span>Updated {new Date(repo.updated_at).toLocaleDateString()}</span>
                          </div>
                        </div>
                        
                        <GitBranch className="w-4 h-4 text-gray-400 mt-1" />
                      </div>
                    </div>
                  ))
                )}
              </div>

              <div className="flex space-x-3">
                <Button
                  variant="outline"
                  onClick={() => setStep('auth')}
                  className="flex-1"
                >
                  Back
                </Button>
                <Button
                  onClick={handleImportRepository}
                  disabled={!selectedRepo}
                  className="flex-1"
                >
                  <Github className="w-4 h-4 mr-2" />
                  Import Repository
                </Button>
              </div>
            </div>
          )}

          {step === 'importing' && (
            <div className="text-center py-8">
              <Loader2 className="w-16 h-16 text-blue-500 mx-auto mb-4 animate-spin" />
              <h4 className="text-xl font-semibold text-white mb-2">Importing Repository</h4>
              <p className="text-gray-400 mb-4">
                Cloning <strong>{selectedRepo?.name}</strong> from GitHub...
              </p>
              <div className="bg-gray-700 rounded-lg p-4">
                <div className="flex items-center space-x-2 text-sm text-gray-300">
                  <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse"></div>
                  <span>This may take a few moments depending on repository size</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};