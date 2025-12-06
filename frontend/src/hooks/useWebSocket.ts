import { useEffect, useRef, useState, useCallback } from 'react';
import { useAuth } from '../contexts/AuthContext';

export interface WebSocketMessage {
  type: string;
  channel?: string;
  timestamp?: string;
  data?: Record<string, unknown>;
  message?: string;
  alert_id?: string;
  incident_id?: string;
  [key: string]: unknown;
}

type MessageHandler = (message: WebSocketMessage) => void;

interface UseWebSocketReturn {
  isConnected: boolean;
  lastMessage: WebSocketMessage | null;
  subscribe: (channel: string) => void;
  unsubscribe: (channel: string) => void;
  addMessageHandler: (handler: MessageHandler) => () => void;
}

function getWebSocketUrl(): string {
  const hostname = typeof window !== 'undefined' ? window.location.hostname : 'localhost';
  return `ws://${hostname}:8000/api/v1/ws`;
}

export function useWebSocket(): UseWebSocketReturn {
  const { token } = useAuth();
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const handlersRef = useRef<Set<MessageHandler>>(new Set());
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef = useRef(true);

  const connect = useCallback(() => {
    // Don't connect if no token or already connected
    if (!token || wsRef.current?.readyState === WebSocket.OPEN) {
      return;
    }

    // Don't connect if already connecting
    if (wsRef.current?.readyState === WebSocket.CONNECTING) {
      return;
    }

    try {
      const wsUrl = getWebSocketUrl();
      const ws = new WebSocket(`${wsUrl}?token=${token}`);

      ws.onopen = () => {
        if (mountedRef.current) {
          console.log('WebSocket connected');
          setIsConnected(true);
        }
      };

      ws.onmessage = (event) => {
        if (!mountedRef.current) return;

        try {
          const message: WebSocketMessage = JSON.parse(event.data);
          setLastMessage(message);

          // Call all registered handlers
          handlersRef.current.forEach(handler => {
            try {
              handler(message);
            } catch (e) {
              console.error('Error in WebSocket message handler:', e);
            }
          });
        } catch (e) {
          console.error('Failed to parse WebSocket message:', e);
        }
      };

      ws.onclose = () => {
        if (!mountedRef.current) return;

        console.log('WebSocket disconnected');
        setIsConnected(false);
        wsRef.current = null;

        // Attempt to reconnect after 5 seconds if we still have a token
        if (token && mountedRef.current) {
          reconnectTimeoutRef.current = setTimeout(() => {
            if (mountedRef.current) {
              connect();
            }
          }, 5000);
        }
      };

      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
      };

      wsRef.current = ws;
    } catch (e) {
      console.error('Failed to create WebSocket connection:', e);
    }
  }, [token]);

  useEffect(() => {
    mountedRef.current = true;

    if (token) {
      connect();
    }

    return () => {
      mountedRef.current = false;

      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = null;
      }

      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [connect, token]);

  const subscribe = useCallback((channel: string) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ action: 'subscribe', channel }));
    }
  }, []);

  const unsubscribe = useCallback((channel: string) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ action: 'unsubscribe', channel }));
    }
  }, []);

  const addMessageHandler = useCallback((handler: MessageHandler) => {
    handlersRef.current.add(handler);
    return () => {
      handlersRef.current.delete(handler);
    };
  }, []);

  return {
    isConnected,
    lastMessage,
    subscribe,
    unsubscribe,
    addMessageHandler,
  };
}
