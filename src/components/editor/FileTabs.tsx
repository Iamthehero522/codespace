// src/components/editor/FileTabs.tsx
import React from 'react';
import { X } from 'lucide-react';

interface OpenFile {
  filePath: string;
  content: string;
  language: string;
  isDirty: boolean;
}

interface FileTabsProps {
  openFiles: OpenFile[];
  activeFilePath: string;
  onTabClick: (filePath: string) => void;
  onCloseTab: (filePath: string) => void;
}

export const FileTabs: React.FC<FileTabsProps> = ({
  openFiles,
  activeFilePath,
  onTabClick,
  onCloseTab,
}) => {
  if (openFiles.length === 0) {
    return null;
  }

  return (
    <div className="flex items-center bg-gray-800 border-b border-gray-700 overflow-x-auto whitespace-nowrap">
      {openFiles.map((file) => (
        <div
          key={file.filePath}
          className={`
            flex items-center px-4 py-2 text-sm cursor-pointer transition-colors duration-200 border-r border-gray-700
            ${file.filePath === activeFilePath
              ? 'bg-gray-900 text-white border-b-2 border-blue-500'
              : 'text-gray-400 hover:bg-gray-700 hover:text-white'
            }
          `}
          onClick={() => onTabClick(file.filePath)}
        >
          <span className="truncate max-w-[150px]">
            {file.filePath.split('/').pop()}
          </span>
          {file.isDirty && (
            <span className="ml-2 w-2 h-2 bg-blue-400 rounded-full flex-shrink-0"></span>
          )}
          <button
            onClick={(e) => {
              e.stopPropagation(); // Prevent tab click when closing
              onCloseTab(file.filePath);
            }}
            className="ml-3 p-1 rounded-full hover:bg-gray-600 text-gray-400 hover:text-white transition-colors"
          >
            <X className="w-3 h-3" />
          </button>
        </div>
      ))}
    </div>
  );
};
