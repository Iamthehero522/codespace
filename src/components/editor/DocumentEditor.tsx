//src/components/editor/DocumentEditor.tsx
import React, { useState, useRef, useEffect } from 'react';
import { 
  Bold, 
  Italic, 
  Underline, 
  AlignLeft, 
  AlignCenter, 
  AlignRight,
  List,
  ListOrdered,
  Link,
  Image,
  Save,
  Share,
  Download,
  MoreHorizontal
} from 'lucide-react';

interface DocumentEditorProps {
  document?: {
    id?: string;
    title: string;
    content: string;
  };
  /** when true, prevent editing and show alert */
  readOnly?: boolean;
  onSave?: (title: string, content: string) => void;
  onTitleChange?: (title: string) => void;
}

export const DocumentEditor: React.FC<DocumentEditorProps> = ({
  document,
  onSave,
  onTitleChange,
  readOnly = false,
}) => {
  const [title, setTitle] = useState(document?.title || 'Untitled Document');
  const [content, setContent] = useState(document?.content || '');
  const [isEditing, setIsEditing] = useState(false);
  const editorRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (document) {
      setTitle(document.title);
      setContent(document.content);
    }
  }, [document]);

  const handleTitleChange = (newTitle: string) => {
    setTitle(newTitle);
    onTitleChange?.(newTitle);
  };

  const handleSave = () => {
    onSave?.(title, content);
  };

  const formatText = (command: string, value?: string) => {
    document.execCommand(command, false, value);
    if (editorRef.current) {
      setContent(editorRef.current.innerHTML);
    }
  };

  const toolbarButtons = [
    { icon: Bold, command: 'bold', label: 'Bold' },
    { icon: Italic, command: 'italic', label: 'Italic' },
    { icon: Underline, command: 'underline', label: 'Underline' },
    { icon: AlignLeft, command: 'justifyLeft', label: 'Align Left' },
    { icon: AlignCenter, command: 'justifyCenter', label: 'Align Center' },
    { icon: AlignRight, command: 'justifyRight', label: 'Align Right' },
    { icon: List, command: 'insertUnorderedList', label: 'Bullet List' },
    { icon: ListOrdered, command: 'insertOrderedList', label: 'Numbered List' },
  ];

  return (
    <div className="flex flex-col h-full bg-white">
      {/* Toolbar */}
      <div className="border-b border-gray-200 p-4">
        <div className="flex items-center justify-between mb-4">
          {/* Document Title */}
          <input
            type="text"
            value={title}
            onChange={(e) => handleTitleChange(e.target.value)}
            className="text-xl font-semibold text-gray-900 bg-transparent border-none focus:outline-none focus:ring-0 flex-1 mr-4"
            placeholder="Untitled Document"
          />

          {/* Action Buttons */}
          <div className="flex items-center space-x-2">
            <button
              onClick={handleSave}
              className="flex items-center space-x-2 px-3 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
            >
              <Save className="w-4 h-4" />
              <span>Save</span>
            </button>
            <button className="flex items-center space-x-2 px-3 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors">
              <Share className="w-4 h-4" />
              <span>Share</span>
            </button>
            <button className="p-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors">
              <MoreHorizontal className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Formatting Toolbar */}
        <div className="flex items-center space-x-1 bg-gray-50 p-2 rounded-lg">
          {toolbarButtons.map((button, index) => {
            const Icon = button.icon;
            return (
              <button
                key={index}
                onClick={() => formatText(button.command)}
                className="p-2 hover:bg-white rounded transition-colors"
                title={button.label}
              >
                <Icon className="w-4 h-4 text-gray-600" />
              </button>
            );
          })}
          
          <div className="w-px h-6 bg-gray-300 mx-2"></div>
          
          <button
            onClick={() => formatText('createLink', prompt('Enter URL:') || '')}
            className="p-2 hover:bg-white rounded transition-colors"
            title="Insert Link"
          >
            <Link className="w-4 h-4 text-gray-600" />
          </button>
          
          <button
            className="p-2 hover:bg-white rounded transition-colors"
            title="Insert Image"
          >
            <Image className="w-4 h-4 text-gray-600" />
          </button>
        </div>
      </div>

      {/* Editor */}
      <div className="flex-1 p-8 overflow-auto">
        <div className="max-w-4xl mx-auto">
          <div
            ref={editorRef}
            contentEditable={!readOnly}
            className="min-h-96 p-6 bg-white rounded-lg border border-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            style={{ 
              lineHeight: '1.6',
              fontSize: '16px',
              fontFamily: 'system-ui, -apple-system, sans-serif'
            }}
            onInput={(e) => {
              if (readOnly) {
                // prevent user edits
                e.preventDefault();
                alert("Cannot edit on view only editor");
                return;
              }
              setContent(e.currentTarget.innerHTML);
              setIsEditing(true);
            }}
            onBlur={() => setIsEditing(false)}
            dangerouslySetInnerHTML={{ __html: content }}
            placeholder="Start writing your document..."
          />
        </div>
      </div>

      {/* Status Bar */}
      <div className="border-t border-gray-200 px-8 py-2 flex items-center justify-between text-sm text-gray-500">
        <div className="flex items-center space-x-4">
          <span>Words: {content.replace(/<[^>]*>/g, '').split(' ').filter(Boolean).length}</span>
          <span>Characters: {content.replace(/<[^>]*>/g, '').length}</span>
        </div>
        <div className="flex items-center space-x-2">
          {isEditing && (
            <span className="flex items-center space-x-1">
              <div className="w-2 h-2 bg-yellow-400 rounded-full animate-pulse"></div>
              <span>Editing...</span>
            </span>
          )}
          <span>Last saved: Just now</span>
        </div>
      </div>
    </div>
  );
};
