//src/components/editor/ProjectFileSidebar.tsx
import React, { useState, useEffect } from 'react';
import { 
  Folder, 
  FolderOpen, 
  FileText, 
  ChevronRight, 
  ChevronDown,
  File,
  Image,
  Code,
  Settings
} from 'lucide-react';

interface ProjectFile {
  id: string;
  relative_path: string;
  is_directory: boolean;
  size?: number;
  mime_type?: string;
}

interface FileTreeNode {
  name: string;
  path: string;
  isDirectory: boolean;
  children?: FileTreeNode[];
  file?: ProjectFile;
}

interface ProjectFileSidebarProps {
  projectId: string;
  files: ProjectFile[];
  onOpenFileInTab: (filePath: string) => void;
  selectedFile?: string;
}

const getFileIcon = (fileName: string, mimeType?: string) => {
  const ext = fileName.split('.').pop()?.toLowerCase();
  
  if (mimeType?.startsWith('image/')) {
    return <Image className="w-4 h-4 text-purple-400" />;
  }
  
  switch (ext) {
    case 'js':
    case 'jsx':
      return <Code className="w-4 h-4 text-yellow-400" />;
    case 'ts':
    case 'tsx':
      return <Code className="w-4 h-4 text-blue-400" />;
    case 'py':
      return <Code className="w-4 h-4 text-green-400" />;
    case 'html':
      return <Code className="w-4 h-4 text-orange-400" />;
    case 'css':
    case 'scss':
      return <Code className="w-4 h-4 text-blue-300" />;
    case 'json':
      return <Settings className="w-4 h-4 text-yellow-300" />;
    case 'md':
      return <FileText className="w-4 h-4 text-gray-400" />;
    case 'java':
      return <Code className="w-4 h-4 text-red-400" />;
    case 'cpp':
    case 'c':
      return <Code className="w-4 h-4 text-blue-500" />;
    case 'php':
      return <Code className="w-4 h-4 text-purple-500" />;
    case 'rb':
      return <Code className="w-4 h-4 text-red-500" />;
    case 'go':
      return <Code className="w-4 h-4 text-cyan-400" />;
    case 'rs':
      return <Code className="w-4 h-4 text-orange-500" />;
    case 'xml':
      return <Code className="w-4 h-4 text-green-300" />;
    case 'yml':
    case 'yaml':
      return <Settings className="w-4 h-4 text-purple-300" />;
    default:
      return <File className="w-4 h-4 text-gray-400" />;
  }
};

const buildFileTree = (files: ProjectFile[]): FileTreeNode[] => {
  const tree: FileTreeNode[] = [];
  const pathMap = new Map<string, FileTreeNode>();

  // Sort files to ensure directories come before their contents
  const sortedFiles = [...files].sort((a, b) => {
    if (a.is_directory && !b.is_directory) return -1;
    if (!a.is_directory && b.is_directory) return 1;
    return a.relative_path.localeCompare(b.relative_path);
  });

  for (const file of sortedFiles) {
    const parts = file.relative_path.split('/').filter(Boolean);
    let currentPath = '';
    let currentLevel = tree;

    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      currentPath = currentPath ? `${currentPath}/${part}` : part;
      
      let node = pathMap.get(currentPath);
      
      if (!node) {
        node = {
          name: part,
          path: currentPath,
          isDirectory: i < parts.length - 1 || file.is_directory,
          children: i < parts.length - 1 || file.is_directory ? [] : undefined,
          file: i === parts.length - 1 ? file : undefined
        };
        
        pathMap.set(currentPath, node);
        currentLevel.push(node);
      }
      
      if (node.children) {
        currentLevel = node.children;
      }
    }
  }

  return tree;
};

const FileTreeItem: React.FC<{
  node: FileTreeNode;
  level: number;
  onOpenFileInTab: (filePath: string) => void;
  selectedFile?: string;
  expandedFolders: Set<string>;
  onToggleFolder: (path: string) => void;
}> = ({ node, level, onOpenFileInTab, selectedFile, expandedFolders, onToggleFolder }) => {
  const isExpanded = expandedFolders.has(node.path);
  const isSelected = selectedFile === node.path;

  const handleClick = () => {
    if (node.isDirectory) {
      onToggleFolder(node.path);
    } else {
      onOpenFileInTab(node.path);
    }
  };

  return (
    <div>
      <div
        className={`
          flex items-center space-x-2 px-2 py-1 cursor-pointer hover:bg-gray-700 rounded
          ${isSelected ? 'bg-blue-600 text-white' : 'text-gray-300'}
        `}
        style={{ paddingLeft: `${level * 12 + 8}px` }}
        onClick={handleClick}
      >
        {node.isDirectory ? (
          <>
            {isExpanded ? (
              <ChevronDown className="w-4 h-4 text-gray-400" />
            ) : (
              <ChevronRight className="w-4 h-4 text-gray-400" />
            )}
            {isExpanded ? (
              <FolderOpen className="w-4 h-4 text-blue-400" />
            ) : (
              <Folder className="w-4 h-4 text-blue-400" />
            )}
          </>
        ) : (
          <>
            <div className="w-4" /> {/* Spacer for alignment */}
            {getFileIcon(node.name, node.file?.mime_type)}
          </>
        )}
        <span className="text-sm truncate">{node.name}</span>
      </div>
      
      {node.isDirectory && isExpanded && node.children && (
        <div>
          {node.children.map((child) => (
            <FileTreeItem
              key={child.path}
              node={child}
              level={level + 1}
              onOpenFileInTab={onOpenFileInTab}
              selectedFile={selectedFile}
              expandedFolders={expandedFolders}
              onToggleFolder={onToggleFolder}
            />
          ))}
        </div>
      )}
    </div>
  );
};

export const ProjectFileSidebar: React.FC<ProjectFileSidebarProps> = ({
  projectId,
  files,
  onOpenFileInTab,
  selectedFile,
}) => {
  const [expandedFolders, setExpandedFolders] = useState<Set<string>>(new Set());
  const [fileTree, setFileTree] = useState<FileTreeNode[]>([]);

  useEffect(() => {
    const tree = buildFileTree(files);
    setFileTree(tree);
    
    // Auto-expand root level folders
    const rootFolders = tree.filter(node => node.isDirectory).map(node => node.path);
    setExpandedFolders(new Set(rootFolders));
  }, [files]);

  const handleToggleFolder = (path: string) => {
    const newExpanded = new Set(expandedFolders);
    if (newExpanded.has(path)) {
      newExpanded.delete(path);
    } else {
      newExpanded.add(path);
    }
    setExpandedFolders(newExpanded);
  };

  return (
    <div className="w-64 bg-gray-800 border-r border-gray-700 flex flex-col h-full">
      <div className="p-4 border-b border-gray-700">
        <h3 className="text-sm font-medium text-gray-300 uppercase tracking-wide">
          Project Files
        </h3>
      </div>
      
      <div className="flex-1 overflow-auto p-2">
        {fileTree.length === 0 ? (
          <div className="text-center py-8">
            <Folder className="w-8 h-8 text-gray-600 mx-auto mb-2" />
            <p className="text-sm text-gray-500">No files found</p>
          </div>
        ) : (
          <div className="space-y-1">
            {fileTree.map((node) => (
              <FileTreeItem
                key={node.path}
                node={node}
                level={0}
                onOpenFileInTab={onOpenFileInTab}
                selectedFile={selectedFile}
                expandedFolders={expandedFolders}
                onToggleFolder={handleToggleFolder}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
