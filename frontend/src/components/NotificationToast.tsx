import { useEffect, useState } from 'react';
import { AlertTriangle, Bell, CheckCircle, FileWarning, X, Zap } from 'lucide-react';
import { useWebSocket } from '../hooks/useWebSocket';
import type { WebSocketMessage } from '../hooks/useWebSocket';

interface Notification {
  id: string;
  type: string;
  title: string;
  message: string;
  timestamp: Date;
  severity?: 'info' | 'warning' | 'error' | 'success';
}

export default function NotificationToast() {
  const { addMessageHandler } = useWebSocket();
  const [notifications, setNotifications] = useState<Notification[]>([]);

  useEffect(() => {
    const removeHandler = addMessageHandler((message: WebSocketMessage) => {
      const notification = parseNotification(message);
      if (notification) {
        setNotifications(prev => [notification, ...prev].slice(0, 5));

        // Auto-remove after 10 seconds
        setTimeout(() => {
          setNotifications(prev => prev.filter(n => n.id !== notification.id));
        }, 10000);
      }
    });

    return removeHandler;
  }, [addMessageHandler]);

  const removeNotification = (id: string) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
  };

  if (notifications.length === 0) {
    return null;
  }

  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm">
      {notifications.map(notification => (
        <div
          key={notification.id}
          className={`
            p-4 rounded-lg shadow-lg border animate-slide-in bg-white
            ${notification.severity === 'error' ? 'border-red-300' : ''}
            ${notification.severity === 'warning' ? 'border-yellow-300' : ''}
            ${notification.severity === 'success' ? 'border-green-300' : ''}
            ${notification.severity === 'info' ? 'border-blue-300' : ''}
          `}
        >
          <div className="flex items-start gap-3">
            {getIcon(notification.type, notification.severity)}
            <div className="flex-1 min-w-0">
              <p className="font-medium text-sm text-gray-900">
                {notification.title}
              </p>
              <p className="text-sm text-gray-600 truncate">
                {notification.message}
              </p>
            </div>
            <button
              onClick={() => removeNotification(notification.id)}
              className="text-gray-400 hover:text-gray-600"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}

function getIcon(type: string, severity?: string) {
  const className = `w-5 h-5 ${
    severity === 'error' ? 'text-red-500' :
    severity === 'warning' ? 'text-yellow-500' :
    severity === 'success' ? 'text-green-500' :
    'text-blue-500'
  }`;

  if (type.includes('alert')) {
    return <AlertTriangle className={className} />;
  }
  if (type.includes('incident')) {
    return <FileWarning className={className} />;
  }
  if (type.includes('playbook')) {
    return <Zap className={className} />;
  }
  if (type.includes('completed') || type.includes('success')) {
    return <CheckCircle className={className} />;
  }
  return <Bell className={className} />;
}

function parseNotification(message: WebSocketMessage): Notification | null {
  const id = `${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
  const timestamp = new Date();

  switch (message.type) {
    case 'alert_created':
      return {
        id,
        type: 'alert',
        title: 'New Alert',
        message: (message.data as { title?: string })?.title || 'A new alert has been created',
        timestamp,
        severity: getSeverityFromAlert(message.data as { severity?: string }),
      };

    case 'alert_updated':
      return {
        id,
        type: 'alert',
        title: 'Alert Updated',
        message: `Alert ${message.alert_id || ''} has been updated`,
        timestamp,
        severity: 'info',
      };

    case 'incident_created':
      return {
        id,
        type: 'incident',
        title: 'New Incident',
        message: (message.data as { title?: string })?.title || 'A new incident has been created',
        timestamp,
        severity: 'warning',
      };

    case 'incident_updated':
      return {
        id,
        type: 'incident',
        title: 'Incident Updated',
        message: `Incident ${message.incident_id || ''} has been updated`,
        timestamp,
        severity: 'info',
      };

    case 'playbook_execution_started':
    case 'execution_started':
      return {
        id,
        type: 'playbook',
        title: 'Playbook Started',
        message: (message.data as { playbook_name?: string })?.playbook_name || 'A playbook has started executing',
        timestamp,
        severity: 'info',
      };

    case 'playbook_step_started':
    case 'step_started':
      return {
        id,
        type: 'playbook',
        title: 'Playbook Step',
        message: `Executing step: ${(message.data as { step_name?: string })?.step_name || 'Unknown'}`,
        timestamp,
        severity: 'info',
      };

    case 'playbook_execution_completed':
    case 'execution_completed':
      return {
        id,
        type: 'playbook',
        title: 'Playbook Completed',
        message: 'Playbook execution completed successfully',
        timestamp,
        severity: 'success',
      };

    case 'playbook_execution_failed':
    case 'execution_failed':
      return {
        id,
        type: 'playbook',
        title: 'Playbook Failed',
        message: (message.data as { error?: string })?.error || 'Playbook execution failed',
        timestamp,
        severity: 'error',
      };

    case 'connected':
      return {
        id,
        type: 'system',
        title: 'Connected',
        message: 'Real-time updates enabled',
        timestamp,
        severity: 'success',
      };

    default:
      return null;
  }
}

function getSeverityFromAlert(data?: { severity?: string }): 'info' | 'warning' | 'error' | 'success' {
  const severity = data?.severity?.toLowerCase();
  if (severity === 'critical' || severity === 'high') {
    return 'error';
  }
  if (severity === 'medium') {
    return 'warning';
  }
  return 'info';
}
