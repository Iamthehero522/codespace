
//codespace/src/contexts/AuthContext.tsx
import React, { createContext, useState, useEffect, useContext, ReactNode } from 'react';
import axios from 'axios';
import { API_URL } from '../config';
import { getOrCreateDeviceId } from '../utils/device'; // ⬅️ you’ll create this

interface User {
  id: string;
  email: string;
  name: string;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  loading: boolean;
  error: string | null;
  setUser: (user: User | null) => void;
  login: (email: string, password: string) => Promise<void>;
  register: (name: string, email: string, password: string) => Promise<void>;
  logout: () => void;
  // Header.tsx expects signOut()
  signOut: () => void;
  clearError: () => void;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  token: null,
  loading: false,
  error: null,
  setUser: () => {},
  login: async () => {},
  register: async () => {},
  logout: () => {},
  signOut: () => {},
  clearError: () => {},
});

export const useAuth = () => useContext(AuthContext);

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, _setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'));
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const setUser = (user: User | null) => {
    _setUser(user);
  };

  useEffect(() => {
    const fetchUser = async () => {
      if (token) {
        try {
          setLoading(true);
           const response = await axios.get(
             `${API_URL}/api/auth/me`,
             { headers: { Authorization: `Bearer ${token}` } }
           );
          _setUser(response.data.user);
        } catch (err) {
          console.error('Failed to fetch user:', err);
          localStorage.removeItem('token');
          setToken(null);
          _setUser(null);
        } finally {
          setLoading(false);
        }
      }
    };

    fetchUser();
  }, [token]);

  const login = async (email: string, password: string) => {
    try {
      setLoading(true);
      setError(null);
      const deviceId = getOrCreateDeviceId(); // 🔐 generate or get stored device ID
      console.log('🔍 [AuthContext.login] API_URL=', API_URL);
      console.log('🔍 [AuthContext.login] payload=', { email, password, deviceId });
      const response = await axios.post(`${API_URL}/api/auth/login`, { email, password, deviceId });
      const { token: newToken, user: userData } = response.data;
      localStorage.setItem('token', newToken);
      setToken(newToken);
      _setUser(userData);
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to login. Please try again.');
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const register = async (name: string, email: string, password: string) => {
    try {
      setLoading(true);
      setError(null);
      const response = await axios.post(`${API_URL}/api/auth/register`, { name, email, password });
      const { token: newToken, user: userData } = response.data;
      localStorage.setItem('token', newToken);
      setToken(newToken);
      _setUser(userData);
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to register. Please try again.');
      throw err;
    } finally {
      setLoading(false);
    }
  };

    const logout = async () => {
      try {
        if (token) {
          await axios.post(
            `${API_URL}/api/auth/logout`,
            {},
            { headers: { Authorization: `Bearer ${token}` } }
          );
        }
      } catch (err) {
        console.error('Error during logout:', err);
      } finally {
        localStorage.removeItem('token');
        setToken(null);
        _setUser(null);
      }
    };

  const clearError = () => {
    setError(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        loading,
        error,
        setUser,
        login,
        register,
        logout,
        signOut: logout,
        clearError,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};
