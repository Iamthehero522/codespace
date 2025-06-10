//src/pages/LoginPage.tsx
import React from 'react';
import { AuthLayout } from '../components/auth/AuthLayout';
import { LoginForm } from '../components/auth/LoginForm';

export const LoginPage: React.FC = () => {
  return (
    <AuthLayout
      title="Welcome to CodeSpace"
      subtitle="Sign in to start coding collaboratively"
    >
      <LoginForm />
    </AuthLayout>
  );
};
