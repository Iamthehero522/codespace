import React from 'react';
import { FileText, Star, MoreVertical, Clock } from 'lucide-react';
import { Link } from 'react-router-dom';

interface Document {
  id: string;
  title: string;
  content: string;
  created_at: string;
  updated_at: string;
  is_starred?: boolean;
}

interface DocumentGridProps {
  documents: Document[];
  loading?: boolean;
}

export const DocumentGrid: React.FC<DocumentGridProps> = ({ documents, loading }) => {
  if (loading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
        {Array.from({ length: 8 }).map((_, i) => (
          <div key={i} className="bg-white rounded-lg border border-gray-200 p-4 animate-pulse">
            <div className="w-full h-32 bg-gray-200 rounded mb-4"></div>
            <div className="h-4 bg-gray-200 rounded mb-2"></div>
            <div className="h-3 bg-gray-200 rounded w-2/3"></div>
          </div>
        ))}
      </div>
    );
  }

  if (documents.length === 0) {
    return (
      <div className="text-center py-12">
        <FileText className="w-16 h-16 text-gray-300 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900 mb-2">No documents yet</h3>
        <p className="text-gray-500 mb-6">Create your first document to get started</p>
        <Link
          to="/document/new"
          className="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          <FileText className="w-4 h-4 mr-2" />
          New Document
        </Link>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
      {documents.map((doc) => (
        <div
          key={doc.id}
          className="bg-white rounded-lg border border-gray-200 hover:shadow-md transition-all duration-200 group"
        >
          <Link to={`/document/${doc.id}`}>
            <div className="p-4">
              {/* Document Preview */}
              <div className="w-full h-32 bg-gradient-to-br from-blue-50 to-purple-50 rounded-lg mb-4 flex items-center justify-center border-2 border-dashed border-gray-200 group-hover:border-blue-300 transition-colors">
                <FileText className="w-8 h-8 text-gray-400 group-hover:text-blue-500 transition-colors" />
              </div>

              {/* Document Info */}
              <div className="flex items-start justify-between mb-2">
                <h3 className="font-medium text-gray-900 truncate flex-1 mr-2">
                  {doc.title || 'Untitled Document'}
                </h3>
                <div className="flex items-center space-x-1">
                  {doc.is_starred && (
                    <Star className="w-4 h-4 text-yellow-400 fill-current" />
                  )}
                  <button className="opacity-0 group-hover:opacity-100 p-1 hover:bg-gray-100 rounded transition-all">
                    <MoreVertical className="w-4 h-4 text-gray-400" />
                  </button>
                </div>
              </div>

              <div className="flex items-center text-xs text-gray-500">
                <Clock className="w-3 h-3 mr-1" />
                <span>
                  {new Date(doc.updated_at).toLocaleDateString()}
                </span>
              </div>
            </div>
          </Link>
        </div>
      ))}
    </div>
  );
};