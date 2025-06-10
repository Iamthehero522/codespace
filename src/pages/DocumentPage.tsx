import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { DocumentEditor } from '../components/editor/DocumentEditor';
import { supabase } from '../lib/supabase';
import { useAuth, AuthProvider } from '../contexts/AuthContext';


export const DocumentPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const { user } = useAuth();
  const navigate = useNavigate();
  const [document, setDocument] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (id === 'new') {
      setDocument({
        title: 'Untitled Document',
        content: '',
      });
      setLoading(false);
    } else if (id && user) {
      fetchDocument();
    }
  }, [id, user]);

  const fetchDocument = async () => {
    try {
      const { data, error } = await supabase
        .from('documents')
        .select('*')
        .eq('id', id)
        .eq('user_id', user?.id)
        .single();

      if (error) throw error;
      setDocument(data);
    } catch (error) {
      console.error('Error fetching document:', error);
      navigate('/dashboard');
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async (title: string, content: string) => {
    try {
      if (id === 'new') {
        // Create new document
        const { data, error } = await supabase
          .from('documents')
          .insert([
            {
              title,
              content,
              user_id: user?.id,
            },
          ])
          .select()
          .single();

        if (error) throw error;
        navigate(`/document/${data.id}`);
      } else {
        // Update existing document
        const { error } = await supabase
          .from('documents')
          .update({ title, content, updated_at: new Date().toISOString() })
          .eq('id', id)
          .eq('user_id', user?.id);

        if (error) throw error;
      }
    } catch (error) {
      console.error('Error saving document:', error);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <DocumentEditor
        document={document}
        onSave={handleSave}
      />
    </div>
  );
};
