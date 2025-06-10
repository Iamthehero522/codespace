// src/hooks/useAutosave.ts
import { useEffect, useRef, useCallback } from 'react';

interface UseAutosaveOptions {
  data: any;
  onSave: (data: any) => Promise<void>;
  delay?: number; // milliseconds
  enabled?: boolean;
}

export const useAutosave = ({ data, onSave, delay = 2000, enabled = true }: UseAutosaveOptions) => {
  const timeoutRef = useRef<NodeJS.Timeout>();
  const lastSavedDataRef = useRef(data);
  const isSavingRef = useRef(false);

  const save = useCallback(async () => {
    if (isSavingRef.current) return;
    
    try {
      isSavingRef.current = true;
      await onSave(data);
      lastSavedDataRef.current = data;
    } catch (error) {
      console.error('Autosave failed:', error);
    } finally {
      isSavingRef.current = false;
    }
  }, [data, onSave]);

  useEffect(() => {
    if (!enabled) return;

    // Clear existing timeout
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
    }

    // Check if data has changed
    const hasChanged = JSON.stringify(data) !== JSON.stringify(lastSavedDataRef.current);
    
    if (hasChanged && !isSavingRef.current) {
      timeoutRef.current = setTimeout(save, delay);
    }

    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
    };
  }, [data, save, delay, enabled]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
    };
  }, []);

  return {
    forceSave: save,
    isSaving: isSavingRef.current,
  };
};