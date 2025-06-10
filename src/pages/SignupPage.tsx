//src/pages/SignupPage.tsx
import React from 'react';
import { AuthLayout } from '../components/auth/AuthLayout';
import { SignupForm } from '../components/auth/SignupForm';

export const SignupPage: React.FC = () => {
  return (
    <AuthLayout
      title="Join CodeSpace"
      subtitle="Create your account and start coding together"
    >
      <SignupForm />
    </AuthLayout>
  );
};
