import React, { useState } from 'react';
import { Terminal, X, Maximize2, Play } from 'lucide-react';

interface OutputPanelProps {
  output: string;
  isRunning: boolean;
  onRunWithInput?: (input: string) => void;
  onClose: () => void;
}

export const OutputPanel: React.FC<OutputPanelProps> = ({ 
  output, 
  isRunning, 
  onRunWithInput, 
  onClose 
}) => {
  const [input, setInput] = useState('');
  const [showInput, setShowInput] = useState(false);

  const handleRunWithInput = () => {
    onRunWithInput?.(input);
    setShowInput(false);
    setInput('');
  };

  return (
    <div className="h-64 bg-gray-900 border-t border-gray-700 flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2 bg-gray-800 border-b border-gray-700">
        <div className="flex items-center space-x-2">
          <Terminal className="w-4 h-4 text-gray-400" />
          <span className="text-sm font-medium text-gray-300">Output</span>
          {isRunning && (
            <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
          )}
        </div>
        
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setShowInput(!showInput)}
            className={`text-xs px-2 py-1 rounded transition-colors ${
              showInput 
                ? 'bg-blue-600 text-white' 
                : 'text-gray-400 hover:text-white bg-gray-700 hover:bg-gray-600'
            }`}
          >
            Input
          </button>
          <button 
            className="text-gray-400 hover:text-white transition-colors"
            title="Maximize"
          >
            <Maximize2 className="w-4 h-4" />
          </button>
          <button 
            className="text-gray-400 hover:text-white transition-colors"
            onClick={onClose}
            title="Close Terminal"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Input Section */}
      {showInput && (
        <div className="border-b border-gray-700 p-3 bg-gray-800">
          <div className="flex items-center space-x-2">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Enter input for your program..."
              className="flex-1 px-3 py-2 bg-gray-700 border border-gray-600 rounded text-sm text-white placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              onKeyPress={(e) => e.key === 'Enter' && handleRunWithInput()}
            />
            <button
              onClick={handleRunWithInput}
              disabled={isRunning}
              className="flex items-center space-x-1 px-3 py-2 bg-green-600 hover:bg-green-700 disabled:bg-green-800 text-white rounded text-sm transition-colors"
            >
              <Play className="w-3 h-3" />
              <span>Run</span>
            </button>
          </div>
        </div>
      )}
      
      {/* Content */}
      <div className="flex-1 p-4 overflow-auto">
        <pre className="text-sm text-gray-300 font-mono whitespace-pre-wrap">
          {output || 'Click "Run" to execute your code...'}
        </pre>
      </div>
    </div>
  );
};
