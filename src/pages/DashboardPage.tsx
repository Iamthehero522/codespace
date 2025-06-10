import React, { useState, useEffect } from 'react';
import { Sidebar } from '../components/dashboard/Sidebar';
import { Header } from '../components/dashboard/Header';
import { ProjectGrid } from '../components/dashboard/ProjectGrid';
import { ZipProjectGrid } from '../components/dashboard/ZipProjectGrid';
import { GitHubProjectGrid } from '../components/dashboard/GitHubProjectGrid';
import { apiClient } from '../lib/api';
import { useAuth } from '../contexts/AuthContext';
import { EnterShareTokenDialog } from '../components/dashboard/EnterShareTokenDialog';
import { Button } from '../components/ui/Button';
import { Link } from 'lucide-react';

export const DashboardPage: React.FC = () => {
  const [projects, setProjects] = useState([]);
  const [zipProjects, setZipProjects] = useState([]);
  const [githubProjects, setGithubProjects] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'code' | 'zip' | 'github'>('code');
  const { user } = useAuth();
  const [showEnterTokenDialog, setShowEnterTokenDialog] = useState(false);

  useEffect(() => {
    if (user) {
      fetchProjects();
    }
  }, [user]);

  const fetchProjects = async () => {
    try {
      setLoading(true);
      const [documentsResponse, projectsResponse, githubResponse] = await Promise.all([
        apiClient.getDocuments(),
        apiClient.getProjects(),
        apiClient.getGitHubProjects().catch(() => ({ projects: [] })) // Fallback if endpoint doesn't exist yet
      ]);
      
      setProjects(documentsResponse.documents || []);
      setZipProjects(projectsResponse.projects || []);
      setGithubProjects(githubResponse.projects || []);
    } catch (error) {
      console.error('Error fetching projects:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleProjectsUpdate = () => {
    fetchProjects();
  };

  return (
    <div className="min-h-screen bg-gray-900 flex">
      <Sidebar onProjectsUpdate={handleProjectsUpdate} />
      <div className="flex-1 flex flex-col">
        <Header />
        <main className="flex-1 p-8">
          <div className="mb-8">
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-2xl font-bold text-white">Recent Projects</h2>
              <Button
                onClick={() => setShowEnterTokenDialog(true)}
                variant="outline"
                className="flex items-center space-x-2"
              >
                <Link className="w-4 h-4" />
                <span>Enter Share Token</span>
              </Button>
            </div>
           
            <p className="text-gray-400">Continue working on your code</p>
          </div>

          {/* Tab Navigation */}
          <div className="mb-6">
            <div className="flex space-x-1 bg-gray-800 p-1 rounded-lg w-fit">
              <button
                onClick={() => setActiveTab('code')}
                className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                  activeTab === 'code'
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                Code Editor Projects ({projects.length})
              </button>
              <button
                onClick={() => setActiveTab('zip')}
                className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                  activeTab === 'zip'
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                ZIP Projects ({zipProjects.length})
              </button>
              <button
                onClick={() => setActiveTab('github')}
                className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                  activeTab === 'github'
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                GitHub Projects ({githubProjects.length})
              </button>
            </div>
          </div>

          {/* Project Grids */}
          {activeTab === 'code' && (
            <ProjectGrid projects={projects} loading={loading} />
          )}
          {activeTab === 'zip' && (
            <ZipProjectGrid projects={zipProjects} loading={loading} />
          )}
          {activeTab === 'github' && (
            <GitHubProjectGrid projects={githubProjects} loading={loading} />
          )}
        </main>

        {/* Enter Share Token Dialog */}
        <EnterShareTokenDialog
          isOpen={showEnterTokenDialog}
          onClose={() => setShowEnterTokenDialog(false)}
        />
      </div>
    </div>
  );
};