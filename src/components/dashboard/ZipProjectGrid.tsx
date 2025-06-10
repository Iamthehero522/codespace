import React from 'react';
import { Archive, Star, MoreVertical, Clock, Users, Folder } from 'lucide-react';
import { Link } from 'react-router-dom';

interface ZipProject {
  id: string;
  name: string;
  description?: string;
  status: 'uploaded' | 'unzipping' | 'ready' | 'error';
  created_at: string;
  updated_at: string;
  file_count?: number;
}

interface ZipProjectGridProps {
  projects: ZipProject[];
  loading?: boolean;
}

const statusColors = {
  uploaded: 'bg-yellow-500',
  unzipping: 'bg-blue-500',
  ready: 'bg-green-500',
  error: 'bg-red-500'
};

const statusLabels = {
  uploaded: 'Uploaded',
  unzipping: 'Processing...',
  ready: 'Ready',
  error: 'Error'
};

export const ZipProjectGrid: React.FC<ZipProjectGridProps> = ({ projects, loading }) => {
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
        <Archive className="w-16 h-16 text-gray-600 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-white mb-2">No ZIP projects yet</h3>
        <p className="text-gray-400 mb-6">Upload your first ZIP project to get started</p>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
      {projects.map((project) => {
        const statusColor = statusColors[project.status];
        const statusLabel = statusLabels[project.status];
        const isClickable = project.status === 'ready';
        
        const ProjectCard = ({ children }: { children: React.ReactNode }) => {
          if (isClickable) {
            return (
              <Link to={`/project/${project.id}`} className="block">
                {children}
              </Link>
            );
          }
          return <div>{children}</div>;
        };

        return (
          <ProjectCard key={project.id}>
            <div className={`bg-gray-800 rounded-lg border border-gray-700 transition-all duration-200 group ${
              isClickable ? 'hover:border-gray-600 hover:shadow-lg cursor-pointer' : 'cursor-default'
            }`}>
              <div className="p-4">
                {/* Project Preview */}
                <div className="w-full h-32 bg-gray-900 rounded-lg mb-4 flex items-center justify-center border border-gray-700 relative overflow-hidden">
                  <Folder className={`w-8 h-8 text-gray-500 ${isClickable ? 'group-hover:text-blue-400' : ''} transition-colors`} />
                  <div className={`absolute top-2 right-2 w-3 h-3 ${statusColor} rounded-full`}></div>
                  <div className="absolute bottom-2 left-2 text-xs text-gray-400 bg-gray-800 px-2 py-1 rounded">
                    {statusLabel}
                  </div>
                </div>

                {/* Project Info */}
                <div className="flex items-start justify-between mb-2">
                  <h3 className="font-medium text-white truncate flex-1 mr-2">
                    {project.name}
                  </h3>
                  <div className="flex items-center space-x-1">
                    <button className="opacity-0 group-hover:opacity-100 p-1 hover:bg-gray-700 rounded transition-all">
                      <MoreVertical className="w-4 h-4 text-gray-400" />
                    </button>
                  </div>
                </div>

                {project.description && (
                  <p className="text-xs text-gray-400 mb-2 line-clamp-2">
                    {project.description}
                  </p>
                )}

                <div className="flex items-center justify-between text-xs text-gray-400">
                  <div className="flex items-center">
                    <Clock className="w-3 h-3 mr-1" />
                    <span>
                      {new Date(project.updated_at).toLocaleDateString()}
                    </span>
                  </div>
                  {project.file_count !== undefined && (
                    <div className="flex items-center">
                      <Archive className="w-3 h-3 mr-1" />
                      <span>{project.file_count} files</span>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </ProjectCard>
        );
      })}
    </div>
  );
};