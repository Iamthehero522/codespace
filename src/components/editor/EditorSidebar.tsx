import React from 'react';
import { 
  FileText, 
  Folder, 
  Search, 
  GitBranch,
  Terminal,
  Package
} from 'lucide-react';

export const EditorSidebar: React.FC = () => {
  return (
    <div className="w-64 bg-gray-800 border-r border-gray-700 flex flex-col">
      {/* File Explorer */}
      <div className="p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-medium text-gray-300 uppercase tracking-wide">Explorer</h3>
          <button className="text-gray-400 hover:text-white">
            <FileText className="w-4 h-4" />
          </button>
        </div>
        
        <div className="space-y-1">
          <div className="flex items-center space-x-2 p-2 hover:bg-gray-700 rounded cursor-pointer">
            <Folder className="w-4 h-4 text-blue-400" />
            <span className="text-sm text-gray-300">src</span>
          </div>
          <div className="flex items-center space-x-2 p-2 hover:bg-gray-700 rounded cursor-pointer ml-4">
            <FileText className="w-4 h-4 text-green-400" />
            <span className="text-sm text-gray-300">main.js</span>
          </div>
          <div className="flex items-center space-x-2 p-2 hover:bg-gray-700 rounded cursor-pointer">
            <FileText className="w-4 h-4 text-orange-400" />
            <span className="text-sm text-gray-300">package.json</span>
          </div>
        </div>
      </div>

      {/* Search */}
      <div className="p-4 border-t border-gray-700">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-medium text-gray-300 uppercase tracking-wide">Search</h3>
          <Search className="w-4 h-4 text-gray-400" />
        </div>
        
        <input
          type="text"
          placeholder="Search in files..."
          className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-sm text-white placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
        />
      </div>

      {/* Git */}
      <div className="p-4 border-t border-gray-700">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-medium text-gray-300 uppercase tracking-wide">Source Control</h3>
          <GitBranch className="w-4 h-4 text-gray-400" />
        </div>
        
        <div className="text-sm text-gray-400">
          No changes
        </div>
      </div>

      {/* Extensions */}
      <div className="p-4 border-t border-gray-700 flex-1">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-medium text-gray-300 uppercase tracking-wide">Extensions</h3>
          <Package className="w-4 h-4 text-gray-400" />
        </div>
        
        <div className="space-y-2">
          <div className="text-sm text-gray-400">
            Prettier - Code formatter
          </div>
          <div className="text-sm text-gray-400">
            ESLint
          </div>
        </div>
      </div>
    </div>
  );
};