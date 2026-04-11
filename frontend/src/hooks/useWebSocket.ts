import { useEffect, useRef, useState, useCallback } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { useQueryClient } from '@tanstack/react-query';

export interface WebSocketMessage {
  type: string;
  channel?: string;
  timestamp?: string;
  data?: Record<string, unknown>;
  message?: string;
  alert_id?: string;
  incident_id?: string;
  message_id?: string;
  [key: string]: unknown;
}

type MessageHandler = (message: WebSocketMessage) => void;

interface UseWebSocketReturn {
  isConnected: boolean;
  lastMessage: WebSocketMessage | null;
  subscribe: (channel: string) => void;
  unsubscribe: (channel: string) => void;
  addMessageHandler: (handler: MessageHandler) => () => void;
  sendMessage: (action: string, data?: Record<string, unknown>) => void;
}

function getWebSocketUrl(): string {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${protocol}//${window.location.host}/api/v1/ws`;
}

const RECONNECT_DELAYS = [1000, 2000, 4000, 8000, 16000, 30000]; // max 30s

// If the WebSocket fails this many times in a row, assume the deployment is
// behind a reverse proxy that strips the Upgrade header (APISIX, some CDNs,
// some ALBs) and fall back to HTTP polling instead of spamming the console.
const MAX_WS_ATTEMPTS_BEFORE_POLLING_FALLBACK = 3;

// Polling interval when running in fallback mode. 15s is a reasonable
// latency for SOC dashboards — alerts/incidents are not sub-second events.
const POLLING_FALLBACK_INTERVAL_MS = 15000;

// Query keys that get invalidated on a "simulated tick" in polling mode.
// Must match the invalidation list inside the ws.onmessage handler below.
const POLLING_INVALIDATION_KEYS = [
  ['alerts'],
  ['incidents'],
  ['playbooks'],
  ['threats'],
  ['iocs'],
  ['compliance'],
] as const;

export function useWebSocket(): UseWebSocketReturn {
  const { token } = useAuth();
  const queryClient = useQueryClient();
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const handlersRef = useRef<Set<MessageHandler>>(new Set());
  const reconnectAttemptRef = useRef(0);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const heartbeatTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef = useRef(true);
  const pollingIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const pollingFallbackActiveRef = useRef(false);

  const startPollingFallback = useCallback(() => {
    if (pollingFallbackActiveRef.current) return;
    pollingFallbackActiveRef.current = true;
    // Quiet single info line so developers know what's happening without
    // a wall of red errors.
    console.info(
      '[PySOAR] Real-time WebSocket unavailable (reverse proxy strips Upgrade headers); ' +
      `falling back to HTTP polling every ${POLLING_FALLBACK_INTERVAL_MS / 1000}s.`
    );
    setIsConnected(false);
    pollingIntervalRef.current = setInterval(() => {
      if (!mountedRef.current) return;
      for (const key of POLLING_INVALIDATION_KEYS) {
        queryClient.invalidateQueries({ queryKey: key });
      }
    }, POLLING_FALLBACK_INTERVAL_MS);
  }, [queryClient]);

  const stopPollingFallback = useCallback(() => {
    if (pollingIntervalRef.current) {
      clearInterval(pollingIntervalRef.current);
      pollingIntervalRef.current = null;
    }
    pollingFallbackActiveRef.current = false;
  }, []);

  // Exponential backoff reconnect delay
  const getReconnectDelay = useCallback(() => {
    const index = Math.min(reconnectAttemptRef.current, RECONNECT_DELAYS.length - 1);
    return RECONNECT_DELAYS[index];
  }, []);

  // Heartbeat ping every 30 seconds
  const startHeartbeat = useCallback(() => {
    const sendPing = () => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ action: 'ping' }));
      }
      if (mountedRef.current) {
        heartbeatTimeoutRef.current = setTimeout(sendPing, 30000);
      }
    };

    if (mountedRef.current) {
      heartbeatTimeoutRef.current = setTimeout(sendPing, 30000);
    }
  }, []);

  const stopHeartbeat = useCallback(() => {
    if (heartbeatTimeoutRef.current) {
      clearTimeout(heartbeatTimeoutRef.current);
      heartbeatTimeoutRef.current = null;
    }
  }, []);

  const connect = useCallback(() => {
    // Don't connect if no token or already connected/connecting
    if (!token) return;

    if (wsRef.current?.readyState === WebSocket.OPEN || wsRef.current?.readyState === WebSocket.CONNECTING) {
      return;
    }

    try {
      const wsUrl = getWebSocketUrl();
      const ws = new WebSocket(`${wsUrl}?token=${token}`);

      ws.onopen = () => {
        if (mountedRef.current) {
          console.log('WebSocket connected');
          setIsConnected(true);
          reconnectAttemptRef.current = 0;
          // If we had fallen back to polling, stop that — WS is back.
          stopPollingFallback();
          startHeartbeat();
        }
      };

      ws.onmessage = (event) => {
        if (!mountedRef.current) return;

        try {
          const message: WebSocketMessage = JSON.parse(event.data);
          setLastMessage(message);

          // Auto-invalidate queries on relevant events for TanStack Query integration
          switch (message.type) {
            case 'alert_created':
            case 'alert_updated':
            case 'alert_escalated':
            case 'alert_resolved':
              queryClient.invalidateQueries({ queryKey: ['alerts'] });
              break;
            case 'incident_created':
            case 'incident_updated':
            case 'incident_escalated':
            case 'incident_resolved':
              queryClient.invalidateQueries({ queryKey: ['incidents'] });
              break;
            case 'playbook_execution_started':
            case 'playbook_execution_completed':
            case 'playbook_execution_failed':
            case 'playbook_step_completed':
              queryClient.invalidateQueries({ queryKey: ['playbooks'] });
              break;
            case 'threat_detected':
            case 'ioc_matched':
              queryClient.invalidateQueries({ queryKey: ['threats'] });
              queryClient.invalidateQueries({ queryKey: ['iocs'] });
              break;
            case 'compliance_violation':
            case 'compliance_check_passed':
              queryClient.invalidateQueries({ queryKey: ['compliance'] });
              break;
          }

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

        stopHeartbeat();
        setIsConnected(false);
        wsRef.current = null;

        // If we've hit the threshold, give up on WebSocket and switch
        // to polling. Don't spam the console or keep hammering the proxy.
        if (reconnectAttemptRef.current >= MAX_WS_ATTEMPTS_BEFORE_POLLING_FALLBACK) {
          startPollingFallback();
          return;
        }

        // Otherwise, silent retry with backoff.
        if (token && mountedRef.current) {
          const delay = getReconnectDelay();
          reconnectAttemptRef.current += 1;

          reconnectTimeoutRef.current = setTimeout(() => {
            if (mountedRef.current) {
              connect();
            }
          }, delay);
        }
      };

      // Swallow error events silently — onclose will run next and handle
      // the retry / fallback logic. Logging the raw error Event object
      // creates noise without any actionable information.
      ws.onerror = () => {
        /* handled by onclose */
      };

      wsRef.current = ws;
    } catch {
      // If the WebSocket constructor itself throws (rare — usually a
      // malformed URL), skip straight to the polling fallback.
      startPollingFallback();
    }
  }, [token, getReconnectDelay, startHeartbeat, stopHeartbeat, queryClient, startPollingFallback, stopPollingFallback]);

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

      stopHeartbeat();
      stopPollingFallback();

      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [connect, token, stopHeartbeat, stopPollingFallback]);

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

  const sendMessage = useCallback((action: string, data?: Record<string, unknown>) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ action, ...data }));
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
    sendMessage,
    addMessageHandler,
  };
}
