import React from 'react';
import { Code2, Star, MoreVertical, Clock, Users } from 'lucide-react';
import { Link } from 'react-router-dom';

interface Project {
  id: string;
  title: string;
  content: string;
  created_at: string;
  updated_at: string;
  is_starred?: boolean;
  language?: string;
}

interface ProjectGridProps {
  projects: Project[];
  loading?: boolean;
}

const languageColors: Record<string, string> = {
  javascript: 'bg-yellow-500',
  typescript: 'bg-blue-500',
  python: 'bg-green-500',
  java: 'bg-orange-500',
  cpp: 'bg-blue-600',
  c: 'bg-gray-500',
  default: 'bg-purple-500'
};

export const ProjectGrid: React.FC<ProjectGridProps> = ({ projects, loading }) => {
  if (loading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
        {Array.from({ length: 8 }).map((_, i) => (
          <div key={i} className="bg-gray-800 rounded-lg border border-gray-700 p-4 animate-pulse">
            <div className="w-full h-32 bg-gray-700 rounded mb-4"></div>
            <div className="h-4 bg-gray-700 rounded mb-2"></div>
            <div className="h-3 bg-gray-700 rounded w-2/3"></div>
          </div>
        ))}
      </div>
    );
  }

  if (projects.length === 0) {
    return (
      <div className="text-center py-12">
        <Code2 className="w-16 h-16 text-gray-600 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-white mb-2">No projects yet</h3>
        <p className="text-gray-400 mb-6">Create your first project to get started</p>
        <Link
          to="/editor/new"
          className="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          <Code2 className="w-4 h-4 mr-2" />
          New Project
        </Link>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
      {projects.map((project) => {
        const language = project.title.split('.').pop()?.toLowerCase() || 'default';
        const colorClass = languageColors[language] || languageColors.default;
        
        return (
          <div
            key={project.id}
            className="bg-gray-800 rounded-lg border border-gray-700 hover:border-gray-600 transition-all duration-200 group hover:shadow-lg"
          >
            <Link to={`/editor/${project.id}`}>
              <div className="p-4">
                {/* Project Preview */}
                <div className="w-full h-32 bg-gray-900 rounded-lg mb-4 flex items-center justify-center border border-gray-700 group-hover:border-blue-500 transition-colors relative overflow-hidden">
                  <Code2 className="w-8 h-8 text-gray-500 group-hover:text-blue-400 transition-colors" />
                  <div className={`absolute top-2 right-2 w-3 h-3 ${colorClass} rounded-full`}></div>
                </div>

                {/* Project Info */}
                <div className="flex items-start justify-between mb-2">
                  <h3 className="font-medium text-white truncate flex-1 mr-2">
                    {project.title || 'Untitled Project'}
                  </h3>
                  <div className="flex items-center space-x-1">
                    {project.is_starred && (
                      <Star className="w-4 h-4 text-yellow-400 fill-current" />
                    )}
                    <button className="opacity-0 group-hover:opacity-100 p-1 hover:bg-gray-700 rounded transition-all">
                      <MoreVertical className="w-4 h-4 text-gray-400" />
                    </button>
                  </div>
                </div>

                <div className="flex items-center justify-between text-xs text-gray-400">
                  <div className="flex items-center">
                    <Clock className="w-3 h-3 mr-1" />
                    <span>
                      {new Date(project.updated_at).toLocaleDateString()}
                    </span>
                  </div>
                  <div className="flex items-center">
                    <Users className="w-3 h-3 mr-1" />
                    <span>1</span>
                  </div>
                </div>
              </div>
            </Link>
          </div>
        );
      })}
    </div>
  );
};