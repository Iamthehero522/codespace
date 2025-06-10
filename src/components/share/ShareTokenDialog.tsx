//src/components/share/ShareTokenDialog.tsx
import React, { useState } from 'react';
import { X, Link, Copy, Check, Loader2, Mail, Send } from 'lucide-react';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { apiClient } from '../../lib/api';

interface ShareTokenDialogProps {
  isOpen: boolean;
  onClose: () => void;
  fileId: string;
  fileName: string;
}

export const ShareTokenDialog: React.FC<ShareTokenDialogProps> = ({
  isOpen,
  onClose,
  fileId,
  fileName,
}) => {
  const [permission, setPermission] = useState<'read' | 'write'>('read');
  const [expiresIn, setExpiresIn] = useState('7d'); // Default to 7 days
  const [generatedShareUrl, setGeneratedShareUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  
  // Email functionality
  const [emailRecipient, setEmailRecipient] = useState('');
  const [emailMessage, setEmailMessage] = useState('');
  const [sendingEmail, setSendingEmail] = useState(false);
  const [emailSent, setEmailSent] = useState(false);
  const [showEmailForm, setShowEmailForm] = useState(false);

  const handleGenerateToken = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setGeneratedShareUrl('');
    setEmailSent(false);

    try {
      const response = await apiClient.generateShareToken(fileId, permission, expiresIn);
      // server now returns the full URL for us
      setGeneratedShareUrl(response.shareUrl);
    } catch (err: any) {
      console.error('Share token generation error:', err);
      setError(err.message || 'Failed to generate share token.');
    } finally {
      setLoading(false);
    }
  };

  const handleSendEmail = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!emailRecipient || !generatedShareUrl) return;

    setSendingEmail(true);
    setError('');

    try {
      await apiClient.sendShareEmail({
        recipientEmail: emailRecipient,
        shareUrl: generatedShareUrl,
        fileName: fileName,
        permission: permission,
        message: emailMessage,
        expiresIn: expiresIn
      });
      
      setEmailSent(true);
      setEmailRecipient('');
      setEmailMessage('');
      setShowEmailForm(false);
    } catch (err: any) {
      console.error('Email sending error:', err);
      setError(err.message || 'Failed to send email. Please try again.');
    } finally {
      setSendingEmail(false);
    }
  };

  const copyShareUrl = async () => {
    try {
      await navigator.clipboard.writeText(generatedShareUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (error) {
      console.error('Failed to copy URL:', error);
    }
  };

  const handleClose = () => {
    setGeneratedShareUrl('');
    setError('');
    setEmailRecipient('');
    setEmailMessage('');
    setEmailSent(false);
    setShowEmailForm(false);
    onClose();
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg shadow-xl max-w-md w-full mx-4 border border-gray-700 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-6 border-b border-gray-700">
          <h3 className="text-lg font-semibold text-white">Share "{fileName}"</h3>
          <button
            onClick={handleClose}
            className="text-gray-400 hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleGenerateToken} className="p-6 space-y-6">
          {error && (
            <div className="bg-red-900/50 border border-red-500/50 rounded-lg p-4">
              <p className="text-sm text-red-300">{error}</p>
            </div>
          )}

          {emailSent && (
            <div className="bg-green-900/50 border border-green-500/50 rounded-lg p-4">
              <p className="text-sm text-green-300">Email sent successfully!</p>
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Permission
            </label>
            <select
              value={permission}
              onChange={(e) => setPermission(e.target.value as 'read' | 'write')}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-white"
            >
              <option value="read">Can view</option>
              <option value="write">Can edit</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Expires In
            </label>
            <select
              value={expiresIn}
              onChange={(e) => setExpiresIn(e.target.value)}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-white"
            >
              <option value="1h">1 hour</option>
              <option value="24h">24 hours</option>
              <option value="7d">7 days</option>
              <option value="30d">30 days</option>
              <option value="">Never expires</option>
            </select>
          </div>

          <Button type="submit" disabled={loading} className="w-full">
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                Generating...
              </>
            ) : (
              <>
                <Link className="w-4 h-4 mr-2" />
                Generate Share Link
              </>
            )}
          </Button>

          {generatedShareUrl && (
            <div className="space-y-4 border-t border-gray-700 pt-6">
              <div className="space-y-2">
                <label className="block text-sm font-medium text-gray-300">
                  Generated Share Link
                </label>
                <div className="flex items-center space-x-2">
                  <input
                    type="text"
                    value={generatedShareUrl}
                    readOnly
                    className="flex-1 px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-sm text-white"
                  />
                  <Button type="button" onClick={copyShareUrl} disabled={copied}>
                    {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                  </Button>
                </div>
                <p className="text-xs text-gray-400">
                  Share this link with others to give them access to your file
                </p>
              </div>

              {/* Email Sharing Section */}
              <div className="space-y-3">
                {!showEmailForm ? (
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => setShowEmailForm(true)}
                    className="w-full"
                  >
                    <Mail className="w-4 h-4 mr-2" />
                    Send via Email
                  </Button>
                ) : (
                  <form onSubmit={handleSendEmail} className="space-y-3">
                    <Input
                      type="email"
                      label="Recipient Email"
                      value={emailRecipient}
                      onChange={(e) => setEmailRecipient(e.target.value)}
                      placeholder="Enter recipient's email"
                      icon={<Mail className="w-4 h-4" />}
                      required
                    />
                    
                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">
                        Personal Message (Optional)
                      </label>
                      <textarea
                        value={emailMessage}
                        onChange={(e) => setEmailMessage(e.target.value)}
                        placeholder="Add a personal message..."
                        rows={3}
                        className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-white placeholder-gray-400 resize-none"
                      />
                    </div>

                    <div className="flex space-x-2">
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => setShowEmailForm(false)}
                        className="flex-1"
                      >
                        Cancel
                      </Button>
                      <Button
                        type="submit"
                        disabled={sendingEmail || !emailRecipient}
                        className="flex-1"
                      >
                        {sendingEmail ? (
                          <>
                            <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                            Sending...
                          </>
                        ) : (
                          <>
                            <Send className="w-4 h-4 mr-2" />
                            Send Email
                          </>
                        )}
                      </Button>
                    </div>
                  </form>
                )}
              </div>
            </div>
          )}
        </form>
      </div>
    </div>
  );
};
