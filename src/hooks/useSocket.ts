// src/hooks/useSocket.ts

import { useEffect, useRef, useState } from 'react';
import { io, Socket } from 'socket.io-client';
import { useAuth } from '../contexts/AuthContext';

interface UseSocketOptions {
  documentId?: string;
  onDocumentChange?: (data: any) => void;
  onUserJoined?: (user: any) => void;
  onUserLeft?: (userId: string) => void;
  onCursorPosition?: (data: any) => void;
  onSelectionChange?: (data: any) => void;
  onActiveUsersUpdate?: (users: any[]) => void;
}

export const useSocket = (options: UseSocketOptions = {}) => {
  const socketRef = useRef<Socket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [activeUsers, setActiveUsers] = useState<any[]>([]);
  const { token, user } = useAuth();
  const lastEmittedDataRef = useRef<any>(null);
  const debounceTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  // Initialize socket when token changes
  useEffect(() => {
    if (!token || !user) return;

    // Use the backend URL without /api suffix for socket connection
    const serverUrl = import.meta.env.VITE_API_URL || 'http://localhost:7001';
    console.log('Connecting to socket server:', serverUrl);
    
    const socket = io(serverUrl, {
      auth: { token },
      transports: ['websocket', 'polling'],
      upgrade: true,
      rememberUpgrade: true,
      timeout: 20000,
      forceNew: true,
    });

    socketRef.current = socket;

    socket.on('connect', () => {
      setIsConnected(true);
      console.log('✅ Connected to socket server with ID:', socket.id);
      
      // Join document room if documentId is provided
      if (options.documentId) {
        console.log('🏠 Joining document room:', options.documentId);
        // only send the document ID; server already knows socket.user
        socket.emit('join-document', options.documentId);
      }
    });
  

    socket.on('disconnect', (reason) => {
      setIsConnected(false);
      console.log('❌ Disconnected from socket server:', reason);
      setActiveUsers([]);
    });

    socket.on('connect_error', (error) => {
      console.error('🔥 Socket connection error:', error);
      setIsConnected(false);
    });

    socket.on('error', (error) => {
      console.error('🔥 Socket error:', error);
    });

    // Handle active users updates
    socket.on('active-users', (users) => {
      console.log('👥 Active users updated:', users);
      setActiveUsers(users || []);
      options.onActiveUsersUpdate?.(users || []);
    });

    // Handle user joined
    socket.on('user-joined', (data) => {
      console.log('👋 User joined:', data);
      if (data.user) {
        setActiveUsers((prev) => {
          const exists = prev.find(u => u.id === data.user.id);
          if (!exists) {
            const newUsers = [...prev, data.user];
            options.onActiveUsersUpdate?.(newUsers);
            return newUsers;
          }
          return prev;
        });
        options.onUserJoined?.(data.user);
      }
    });

    // Handle user left
    socket.on('user-left', (data) => {
      console.log('👋 User left:', data);
      if (data.userId) {
        setActiveUsers((prev) => {
          const newUsers = prev.filter((user) => user.id !== data.userId);
          options.onActiveUsersUpdate?.(newUsers);
          return newUsers;
        });
        options.onUserLeft?.(data.userId);
      }
    });

    // Handle document changes from other users
    socket.on('document-change', (data) => {
      console.log('📝 Document change received:', data);
      // Only apply changes from other users
      if (data.userId !== user.id) {
        options.onDocumentChange?.(data);
      }
    });

    // Handle cursor position updates
    socket.on('cursor-position', (data) => {
      if (data.userId !== user.id) {
        options.onCursorPosition?.(data);
      }
    });

    // Handle selection changes
    socket.on('selection-change', (data) => {
      if (data.userId !== user.id) {
        options.onSelectionChange?.(data);
      }
    });

    return () => {
      if (socketRef.current) {
        console.log('🧹 Cleaning up socket connection');
        if (options.documentId) {
          socketRef.current.emit('leave-document', {
            documentId: options.documentId,
            userId: user.id
          });
        }
        socketRef.current.disconnect();
        socketRef.current = null;
      }
      if (debounceTimeoutRef.current) {
        clearTimeout(debounceTimeoutRef.current);
      }
    };
  }, [token, user?.id]);

  // Emit join-document when documentId changes
  useEffect(() => {
    if (options.documentId && socketRef.current && isConnected) {
      console.log('🔄 Document ID changed, joining room:', options.documentId);
      socketRef.current.emit('join-document', options.documentId);
    }
  }, [options.documentId, isConnected, user]);

  const emitDocumentChange = (data: any) => {
    if (!socketRef.current || !user || !isConnected) {
      console.warn('⚠️ Cannot emit document change: socket not ready');
      return;
    }

    const payload = {
      ...data,
      userId: user.id,
      documentId: options.documentId,
      timestamp: Date.now()
    };

    // Debounce rapid changes for live editing
    if (data.liveEdit) {
      if (debounceTimeoutRef.current) {
        clearTimeout(debounceTimeoutRef.current);
      }
      
      debounceTimeoutRef.current = setTimeout(() => {
        console.log('📤 Emitting debounced document change:', payload);
        socketRef.current?.emit('document-change', payload);
        lastEmittedDataRef.current = payload;
      }, 300); // 300ms debounce for live editing
    } else {
      // Immediate emit for manual saves and other actions
      console.log('📤 Emitting immediate document change:', payload);
      socketRef.current.emit('document-change', payload);
      lastEmittedDataRef.current = payload;
    }
  };

  const emitCursorPosition = (data: any) => {
    if (socketRef.current && user && isConnected) {
      const payload = {
        ...data,
        userId: user.id,
        documentId: options.documentId,
        timestamp: Date.now()
      };
      socketRef.current.emit('cursor-position', payload);
    }
  };

  const emitSelectionChange = (data: any) => {
    if (socketRef.current && user && isConnected) {
      const payload = {
        ...data,
        userId: user.id,
        documentId: options.documentId,
        timestamp: Date.now()
      };
      socketRef.current.emit('selection-change', payload);
    }
  };

  return {
    socket: socketRef.current,
    isConnected,
    activeUsers,
    emitDocumentChange,
    emitCursorPosition,
    emitSelectionChange,
  };
};
