import React, { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { apiClient } from '../lib/api';
import { useAuth } from '../contexts/AuthContext';

export const ShareRedirectPage: React.FC = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, loading: authLoading } = useAuth();
  const [message, setMessage] = useState('Processing share link...');
  const [error, setError] = useState('');

  useEffect(() => {
    const processShareToken = async () => {
      if (authLoading) {
        return; // Wait for auth to load
      }

      if (!user) {
        // Redirect to login with return URL
        navigate('/login', { 
          state: { from: location.pathname + location.search },
          replace: true 
        });
        return;
      }

      const params = new URLSearchParams(location.search);
      const token = params.get('token');

      if (!token) {
        setError('No share token found in the URL.');
        setMessage('');
        return;
      }

      try {
        setMessage('Validating share token...');
        console.log('Processing share token:', token);
        
        const response = await apiClient.accessShareToken(token);
        console.log('Share token response:', response);
        
        setMessage('Access granted! Redirecting to file...');
        
        // Navigate to the appropriate page based on the file
        setTimeout(() => {
          navigate(`/editor/${response.fileId}`, { replace: true });
        }, 1000);
        
      } catch (err: any) {
        console.error('Share token access error:', err);
        setError(err.message || 'Failed to access shared file. The token might be invalid or expired.');
        setMessage('');
      }
    };

    processShareToken();
  }, [location.search, navigate, user, authLoading, location.pathname]);

  return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center">
      <div className="text-center p-8 bg-gray-800 rounded-lg shadow-lg max-w-md w-full mx-4">
        {message && (
          <div className="mb-4">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500 mx-auto mb-4"></div>
            <p className="text-white text-lg">{message}</p>
          </div>
        )}
        
        {error && (
          <div className="mb-4">
            <div className="w-8 h-8 bg-red-500 rounded-full flex items-center justify-center mx-auto mb-4">
              <span className="text-white font-bold">!</span>
            </div>
            <p className="text-red-400 text-lg mb-4">{error}</p>
            <button
              onClick={() => navigate('/dashboard')}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
            >
              Go to Dashboard
            </button>
          </div>
        )}
        
        {!message && !error && (
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto"></div>
        )}
      </div>
    </div>
  );
};