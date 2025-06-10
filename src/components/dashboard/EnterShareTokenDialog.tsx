import React, { useState } from 'react';
import { X, Link, Loader2 } from 'lucide-react';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { apiClient } from '../../lib/api';
import { useNavigate } from 'react-router-dom';

interface EnterShareTokenDialogProps {
  isOpen: boolean;
  onClose: () => void;
}

export const EnterShareTokenDialog: React.FC<EnterShareTokenDialogProps> = ({
  isOpen,
  onClose,
}) => {
  const [tokenInput, setTokenInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const navigate = useNavigate();

  const handleAccessToken = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccessMessage('');

    try {
      // Extract token from the full URL if provided
      let tokenToUse = tokenInput.trim();
      
      // Handle different URL formats
      if (tokenToUse.includes('?token=')) {
        tokenToUse = tokenToUse.split('?token=')[1];
      } else if (tokenToUse.includes('/share?token=')) {
        tokenToUse = tokenToUse.split('/share?token=')[1];
      }

      console.log('Accessing token:', tokenToUse);
      
      const response = await apiClient.accessShareToken(tokenToUse);
      setSuccessMessage('Access granted! Redirecting...');
      
      // Navigate based on the file type or default to editor
      setTimeout(() => {
        navigate(`/editor/${response.fileId}`);
        onClose();
      }, 1000);
      
    } catch (err: any) {
      console.error('Token access error:', err);
      setError(err.message || 'Failed to access shared file. Please check the token and try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    setTokenInput('');
    setError('');
    setSuccessMessage('');
    onClose();
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg shadow-xl max-w-md w-full mx-4 border border-gray-700">
        <div className="flex items-center justify-between p-6 border-b border-gray-700">
          <h3 className="text-lg font-semibold text-white">Enter Share Token</h3>
          <button
            onClick={handleClose}
            className="text-gray-400 hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleAccessToken} className="p-6 space-y-6">
          {error && (
            <div className="bg-red-900/50 border border-red-500/50 rounded-lg p-4">
              <p className="text-sm text-red-300">{error}</p>
            </div>
          )}
          {successMessage && (
            <div className="bg-green-900/50 border border-green-500/50 rounded-lg p-4">
              <p className="text-sm text-green-300">{successMessage}</p>
            </div>
          )}

          <div>
            <Input
              label="Share Token or Link"
              type="text"
              value={tokenInput}
              onChange={(e) => setTokenInput(e.target.value)}
              placeholder="Paste the share token or full link here"
              required
            />
            <p className="text-xs text-gray-400 mt-1">
              You can paste either the token or the full share URL
            </p>
          </div>

          <Button type="submit" disabled={loading || !tokenInput.trim()} className="w-full">
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                Accessing...
              </>
            ) : (
              <>
                <Link className="w-4 h-4 mr-2" />
                Access Shared File
              </>
            )}
          </Button>
        </form>
      </div>
    </div>
  );
};