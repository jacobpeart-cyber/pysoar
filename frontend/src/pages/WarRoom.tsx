import { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Shield,
  Users,
  Clock,
  FileText,
  Plus,
  X,
  Send,
  AlertTriangle,
  Archive,
} from 'lucide-react';
import clsx from 'clsx';
import { collaborationApi } from '../api/endpoints';

// ---------------------------------------------------------------------------
// Types matching backend response schemas
// ---------------------------------------------------------------------------

interface WarRoomType {
  id: string;
  name: string;
  description: string | null;
  room_type: string;
  status: string; // active, standby, archived
  severity_level: string;
  commander_id: string | null;
  participants: string[];
  incident_id: string | null;
  created_by: string;
  created_at: string | null;
  updated_at: string | null;
}

interface ActionItemType {
  id: string;
  room_id: string;
  title: string;
  description: string | null;
  assigned_to: string | null;
  assigned_by: string;
  priority: string; // critical, high, medium, low
  status: string; // pending, in_progress, completed, blocked, cancelled
  due_date: string | null;
  completed_at: string | null;
  notes: string | null;
  created_at: string | null;
  _room_name?: string; // added by frontend aggregation
}

interface MessageType {
  id: string;
  room_id: string;
  sender_id: string;
  sender_name: string;
  content: string;
  message_type: string;
  is_pinned: boolean;
  created_at: string | null;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatTime(dateStr: string | null | undefined): string {
  if (!dateStr) return '--';
  try {
    return new Date(dateStr).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  } catch { return '--'; }
}

function formatDateTime(dateStr: string | null | undefined): string {
  if (!dateStr) return '--';
  try {
    return new Date(dateStr).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  } catch { return '--'; }
}

const severityColors: Record<string, string> = {
  critical: 'bg-red-900/60 text-red-200',
  high: 'bg-orange-900/60 text-orange-200',
  medium: 'bg-yellow-900/60 text-yellow-200',
  low: 'bg-green-900/60 text-green-200',
};

const statusColors: Record<string, string> = {
  active: 'bg-red-900/40 text-red-300',
  standby: 'bg-yellow-900/40 text-yellow-300',
  archived: 'bg-green-900/40 text-green-300',
  pending: 'bg-gray-900/40 text-gray-300',
  in_progress: 'bg-blue-900/40 text-blue-300',
  completed: 'bg-green-900/40 text-green-300',
  blocked: 'bg-red-900/40 text-red-300',
  cancelled: 'bg-gray-900/40 text-gray-400',
};

const priorityColors: Record<string, string> = {
  critical: 'bg-red-900/60 text-red-200',
  high: 'bg-orange-900/60 text-orange-200',
  medium: 'bg-yellow-900/60 text-yellow-200',
  low: 'bg-blue-900/60 text-blue-200',
};

export default function WarRoom() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'rooms' | 'actions' | 'archived'>('rooms');
  const [selectedRoom, setSelectedRoom] = useState<WarRoomType | null>(null);
  const [showCreateRoom, setShowCreateRoom] = useState(false);
  const [showCreateAction, setShowCreateAction] = useState(false);
  const [newMessage, setNewMessage] = useState('');
  const [createError, setCreateError] = useState<string | null>(null);

  // ---------------------------------------------------------------------------
  // Queries
  // ---------------------------------------------------------------------------

  const { data: warRooms = [] } = useQuery<WarRoomType[]>({
    queryKey: ['warRooms'],
    queryFn: async () => {
      const data = await collaborationApi.getWarRooms();
      return Array.isArray(data) ? data : [];
    },
  });

  const { data: allActionItems = [] } = useQuery<ActionItemType[]>({
    queryKey: ['allActionItems'],
    queryFn: async () => {
      const data = await collaborationApi.getAllActionItems();
      return Array.isArray(data) ? data : [];
    },
  });

  const { data: archivedRooms = [] } = useQuery<WarRoomType[]>({
    queryKey: ['archivedRooms'],
    queryFn: async () => {
      const data = await collaborationApi.getArchivedRooms();
      return Array.isArray(data) ? data : [];
    },
    enabled: activeTab === 'archived',
  });

  const { data: roomMessages = [] } = useQuery<MessageType[]>({
    queryKey: ['roomMessages', selectedRoom?.id],
    queryFn: async () => {
      if (!selectedRoom) return [];
      const data = await collaborationApi.getMessages(selectedRoom.id);
      return Array.isArray(data) ? data : [];
    },
    enabled: !!selectedRoom,
  });

  const { data: dashboard } = useQuery({
    queryKey: ['collaborationDashboard'],
    queryFn: collaborationApi.getDashboard,
  });

  // ---------------------------------------------------------------------------
  // Mutations
  // ---------------------------------------------------------------------------

  const createRoomMutation = useMutation({
    mutationFn: async (data: { name: string; description: string; room_type: string; severity_level: string }) => {
      return collaborationApi.createWarRoom(data);
    },
    onSuccess: () => {
      setShowCreateRoom(false);
      setCreateError(null);
      queryClient.invalidateQueries({ queryKey: ['warRooms'] });
    },
    onError: (err: any) => {
      setCreateError(err?.response?.data?.detail || err?.message || 'Failed to create room');
    },
  });

  const createActionMutation = useMutation({
    mutationFn: async (data: { roomId: string; title: string; priority: string; description: string }) => {
      return collaborationApi.createActionItem(data.roomId, {
        title: data.title,
        priority: data.priority,
        description: data.description,
      });
    },
    onSuccess: () => {
      setShowCreateAction(false);
      setCreateError(null);
      queryClient.invalidateQueries({ queryKey: ['allActionItems'] });
    },
    onError: (err: any) => {
      setCreateError(err?.response?.data?.detail || err?.message || 'Failed to create action item');
    },
  });

  const sendMessageMutation = useMutation({
    mutationFn: async (data: { roomId: string; content: string }) => {
      return collaborationApi.sendMessage(data.roomId, { content: data.content });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['roomMessages', selectedRoom?.id] });
    },
  });

  const archiveRoomMutation = useMutation({
    mutationFn: async (roomId: string) => {
      return collaborationApi.archiveWarRoom(roomId);
    },
    onSuccess: () => {
      setSelectedRoom(null);
      queryClient.invalidateQueries({ queryKey: ['warRooms'] });
      queryClient.invalidateQueries({ queryKey: ['archivedRooms'] });
    },
  });

  // ---------------------------------------------------------------------------
  // Derived Stats
  // ---------------------------------------------------------------------------

  const stats = useMemo(() => {
    if (dashboard) {
      return {
        activeRooms: dashboard.active_rooms ?? 0,
        totalActions: dashboard.pending_actions ?? 0,
        overdueActions: dashboard.overdue_actions ?? 0,
        totalParticipants: dashboard.total_participants ?? 0,
      };
    }
    const activeRooms = warRooms.filter((r) => r.status === 'active').length;
    const totalActions = allActionItems.length;
    const overdueActions = allActionItems.filter((a) => {
      if (!a.due_date || a.status === 'completed' || a.status === 'cancelled') return false;
      return new Date(a.due_date) < new Date();
    }).length;
    return { activeRooms, totalActions, overdueActions, totalParticipants: 0 };
  }, [warRooms, allActionItems, dashboard]);

  const handleSendMessage = () => {
    if (newMessage.trim() && selectedRoom) {
      sendMessageMutation.mutate({ roomId: selectedRoom.id, content: newMessage.trim() });
      setNewMessage('');
    }
  };

  const activeRooms = warRooms.filter((r) => r.status === 'active' || r.status === 'standby');

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <div className="min-h-screen bg-gray-900 text-white p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold mb-2 flex items-center gap-3">
            <Shield className="w-8 h-8 text-orange-400" />
            War Room
          </h1>
          <p className="text-gray-400">Incident Response Coordination & Collaboration</p>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-4 gap-4 mb-8">
          <div className={clsx('border rounded-lg p-6', stats.activeRooms > 0 ? 'bg-red-900/20 border-red-700' : 'bg-gray-800 border-gray-700')}>
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Active War Rooms</p>
                <p className="text-3xl font-bold">{stats.activeRooms}</p>
              </div>
              <Shield className="w-8 h-8 text-orange-400" />
            </div>
          </div>

          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Action Items</p>
                <p className="text-3xl font-bold">{stats.totalActions}</p>
              </div>
              <FileText className="w-8 h-8 text-blue-400" />
            </div>
          </div>

          <div className={clsx('border rounded-lg p-6', stats.overdueActions > 0 ? 'bg-red-900/20 border-red-700' : 'bg-gray-800 border-gray-700')}>
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Overdue Actions</p>
                <p className="text-3xl font-bold">{stats.overdueActions}</p>
              </div>
              <AlertTriangle className="w-8 h-8 text-red-400" />
            </div>
          </div>

          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Participants</p>
                <p className="text-3xl font-bold">{stats.totalParticipants}</p>
              </div>
              <Users className="w-8 h-8 text-green-400" />
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="mb-6 border-b border-gray-700">
          <div className="flex gap-8">
            {[
              { id: 'rooms', label: 'Active War Rooms', icon: Shield },
              { id: 'actions', label: 'Action Items', icon: FileText },
              { id: 'archived', label: 'Archived', icon: Archive },
            ].map((tab) => {
              const TabIcon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as typeof activeTab)}
                  className={clsx(
                    'pb-4 px-4 font-medium text-sm flex items-center gap-2 border-b-2 transition-colors',
                    activeTab === tab.id
                      ? 'border-orange-400 text-orange-400'
                      : 'border-transparent text-gray-400 hover:text-white'
                  )}
                >
                  <TabIcon className="w-4 h-4" />
                  {tab.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* ================================================================ */}
        {/* War Rooms Tab                                                     */}
        {/* ================================================================ */}
        {activeTab === 'rooms' && (
          <div>
            <div className="mb-6 flex justify-end">
              <button
                onClick={() => { setShowCreateRoom(true); setCreateError(null); }}
                className="bg-orange-600 hover:bg-orange-700 text-white px-4 py-2 rounded flex items-center gap-2 transition-colors"
              >
                <Plus className="w-4 h-4" />
                New War Room
              </button>
            </div>

            {activeRooms.length === 0 ? (
              <div className="text-center py-16 text-gray-500">
                <Shield className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>No active war rooms. Create one to start coordinating.</p>
              </div>
            ) : (
              <div className="space-y-4">
                {activeRooms.map((room) => (
                  <div
                    key={room.id}
                    onClick={() => setSelectedRoom(room)}
                    className={clsx(
                      'border rounded-lg p-6 cursor-pointer transition-colors',
                      room.severity_level === 'critical'
                        ? 'bg-red-900/20 border-red-700 hover:bg-red-900/30'
                        : 'bg-gray-800 border-gray-700 hover:bg-gray-700/50'
                    )}
                  >
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex-1">
                        <h3 className="text-lg font-semibold text-white mb-2">{room.name}</h3>
                        <div className="flex items-center gap-4 text-sm text-gray-400">
                          <span className="flex items-center gap-1">
                            <Users className="w-4 h-4" />
                            {Array.isArray(room.participants) ? room.participants.length : 0} participants
                          </span>
                          <span className="flex items-center gap-1">
                            <Clock className="w-4 h-4" />
                            Started: {formatDateTime(room.created_at)}
                          </span>
                          {room.description && (
                            <span className="text-gray-500 truncate max-w-xs">{room.description}</span>
                          )}
                        </div>
                      </div>
                      <div className="text-right space-y-1">
                        <span className={clsx('px-3 py-1 rounded text-xs font-medium block', severityColors[room.severity_level] ?? 'bg-gray-900/40 text-gray-300')}>
                          {room.severity_level}
                        </span>
                        <span className={clsx('px-3 py-1 rounded text-xs font-medium block', statusColors[room.status] ?? 'bg-gray-900/40 text-gray-300')}>
                          {room.status}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center justify-between">
                      <span className="text-xs text-gray-500">Type: {room.room_type?.replace(/_/g, ' ')}</span>
                      <button
                        onClick={(e) => { e.stopPropagation(); setSelectedRoom(room); }}
                        className="text-blue-400 hover:text-blue-300 text-sm font-medium transition-colors"
                      >
                        Enter Room &rarr;
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ================================================================ */}
        {/* Action Items Tab                                                  */}
        {/* ================================================================ */}
        {activeTab === 'actions' && (
          <div>
            <div className="mb-6 flex justify-end">
              <button
                onClick={() => { setShowCreateAction(true); setCreateError(null); }}
                className="bg-orange-600 hover:bg-orange-700 text-white px-4 py-2 rounded flex items-center gap-2 transition-colors"
                disabled={activeRooms.length === 0}
                title={activeRooms.length === 0 ? 'Create a war room first' : ''}
              >
                <Plus className="w-4 h-4" />
                New Action Item
              </button>
            </div>

            {allActionItems.length === 0 ? (
              <div className="text-center py-16 text-gray-500">
                <FileText className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>No action items yet.</p>
              </div>
            ) : (
              <div className="space-y-4">
                {allActionItems.map((item) => (
                  <div
                    key={item.id}
                    className={clsx(
                      'border rounded-lg p-6',
                      item.status === 'blocked' ? 'bg-red-900/20 border-red-700'
                        : item.status === 'in_progress' ? 'bg-blue-900/20 border-blue-700'
                        : 'bg-gray-800 border-gray-700'
                    )}
                  >
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex-1">
                        <h3 className="text-lg font-semibold text-white mb-2">{item.title}</h3>
                        {item.description && <p className="text-sm text-gray-400 mb-1">{item.description}</p>}
                        <p className="text-sm text-gray-500">Assigned to: {item.assigned_to || 'Unassigned'}</p>
                      </div>
                      <span className={clsx('px-3 py-1 rounded text-xs font-medium', priorityColors[item.priority] ?? 'bg-gray-900/40 text-gray-300')}>
                        {item.priority}
                      </span>
                    </div>

                    <div className="grid grid-cols-3 gap-4">
                      <div>
                        <p className="text-xs text-gray-400 mb-1">War Room</p>
                        <p className="text-white text-sm">{item._room_name || item.room_id?.slice(0, 8)}</p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-400 mb-1">Due Date</p>
                        <p className="text-white text-sm">{item.due_date ? formatDateTime(item.due_date) : '--'}</p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-400 mb-1">Status</p>
                        <span className={clsx('px-2 py-1 rounded text-xs font-medium inline-block', statusColors[item.status] ?? 'bg-gray-900/40 text-gray-300')}>
                          {item.status?.replace(/_/g, ' ')}
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ================================================================ */}
        {/* Archived Tab                                                      */}
        {/* ================================================================ */}
        {activeTab === 'archived' && (
          <div>
            {archivedRooms.length === 0 ? (
              <div className="text-center py-16 text-gray-500">
                <Archive className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>No archived war rooms.</p>
              </div>
            ) : (
              <div className="space-y-4">
                {archivedRooms.map((room) => (
                  <div key={room.id} className="bg-gray-800 border border-gray-700 rounded-lg p-6">
                    <div className="flex items-start justify-between mb-4">
                      <div>
                        <h3 className="text-lg font-semibold text-white mb-2">{room.name}</h3>
                        <p className="text-sm text-gray-400">{room.description}</p>
                      </div>
                      <span className={clsx('px-3 py-1 rounded text-xs font-medium', severityColors[room.severity_level] ?? 'bg-gray-900/40 text-gray-300')}>
                        {room.severity_level}
                      </span>
                    </div>
                    <div className="flex items-center gap-4 text-sm text-gray-500">
                      <span>Type: {room.room_type?.replace(/_/g, ' ')}</span>
                      <span>Created: {formatDateTime(room.created_at)}</span>
                      <span>{Array.isArray(room.participants) ? room.participants.length : 0} participants</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ================================================================ */}
        {/* War Room Detail Modal (Chat)                                      */}
        {/* ================================================================ */}
        {selectedRoom && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-gray-800 border border-gray-700 rounded-lg max-w-2xl w-full flex flex-col" style={{ maxHeight: '80vh' }}>
              <div className="flex items-start justify-between p-6 border-b border-gray-700">
                <div>
                  <h2 className="text-2xl font-bold text-white mb-1">{selectedRoom.name}</h2>
                  <div className="flex items-center gap-3 text-sm text-gray-400">
                    <span className={clsx('px-2 py-0.5 rounded text-xs font-medium', severityColors[selectedRoom.severity_level])}>
                      {selectedRoom.severity_level}
                    </span>
                    <span>{Array.isArray(selectedRoom.participants) ? selectedRoom.participants.length : 0} participants</span>
                    <span>Started {formatDateTime(selectedRoom.created_at)}</span>
                  </div>
                </div>
                <button onClick={() => setSelectedRoom(null)} className="text-gray-400 hover:text-white transition-colors">
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="flex-1 overflow-y-auto p-6 space-y-4 min-h-[200px]">
                {roomMessages.length === 0 ? (
                  <p className="text-gray-500 text-center py-8">No messages yet. Start the conversation.</p>
                ) : (
                  roomMessages.map((msg) => (
                    <div key={msg.id} className={clsx('rounded-lg p-4', msg.is_pinned ? 'bg-yellow-900/20 border border-yellow-700' : 'bg-gray-700/50')}>
                      <div className="flex items-start justify-between mb-2">
                        <p className="font-semibold text-white">{msg.sender_name || 'Unknown'}</p>
                        <span className="text-xs text-gray-400">{formatTime(msg.created_at)}</span>
                      </div>
                      <p className="text-gray-300">{msg.content}</p>
                    </div>
                  ))
                )}
              </div>

              <div className="border-t border-gray-700 p-6 space-y-3">
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={newMessage}
                    onChange={(e) => setNewMessage(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleSendMessage()}
                    placeholder="Type your message..."
                    className="flex-1 bg-gray-700 border border-gray-600 rounded px-4 py-2 text-white placeholder-gray-500"
                  />
                  <button
                    onClick={handleSendMessage}
                    disabled={!newMessage.trim() || sendMessageMutation.isPending}
                    className="bg-orange-600 hover:bg-orange-700 text-white px-4 py-2 rounded flex items-center gap-2 transition-colors disabled:opacity-50"
                  >
                    <Send className="w-4 h-4" />
                  </button>
                </div>

                <div className="flex gap-2">
                  <button
                    onClick={() => {
                      archiveRoomMutation.mutate(selectedRoom.id);
                    }}
                    disabled={archiveRoomMutation.isPending}
                    className="flex-1 bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded text-sm transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
                  >
                    <Archive className="w-4 h-4" />
                    Archive Room
                  </button>
                  <button
                    onClick={() => setSelectedRoom(null)}
                    className="flex-1 bg-orange-600 hover:bg-orange-700 text-white px-4 py-2 rounded text-sm transition-colors"
                  >
                    Close
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ================================================================ */}
        {/* Create War Room Modal                                             */}
        {/* ================================================================ */}
        {showCreateRoom && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 max-w-md w-full">
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-xl font-bold text-white">New War Room</h2>
                <button onClick={() => setShowCreateRoom(false)} className="text-gray-400 hover:text-white transition-colors">
                  <X className="w-5 h-5" />
                </button>
              </div>

              {createError && (
                <div className="bg-red-900/30 border border-red-700 rounded p-3 text-sm text-red-300 mb-4">{createError}</div>
              )}

              <form className="space-y-4" onSubmit={(e) => {
                e.preventDefault();
                setCreateError(null);
                const fd = new FormData(e.currentTarget);
                createRoomMutation.mutate({
                  name: fd.get('name') as string,
                  description: (fd.get('description') as string) || '',
                  room_type: (fd.get('room_type') as string) || 'incident_response',
                  severity_level: (fd.get('severity_level') as string) || 'medium',
                });
              }}>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Room Name</label>
                  <input name="name" required type="text" className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white placeholder-gray-500" placeholder="e.g., DB Outage Response" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Description</label>
                  <textarea name="description" rows={2} className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white placeholder-gray-500 resize-none" placeholder="Describe the incident..." />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Room Type</label>
                  <select name="room_type" className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white">
                    <option value="incident_response">Incident Response</option>
                    <option value="threat_hunt">Threat Hunt</option>
                    <option value="red_team">Red Team</option>
                    <option value="blue_team">Blue Team</option>
                    <option value="tabletop_exercise">Tabletop Exercise</option>
                    <option value="general">General</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Severity</label>
                  <select name="severity_level" className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white">
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium" selected>Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
                <div className="flex gap-4 mt-6">
                  <button type="button" onClick={() => setShowCreateRoom(false)} className="flex-1 bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded transition-colors">Cancel</button>
                  <button type="submit" disabled={createRoomMutation.isPending} className="flex-1 bg-orange-600 hover:bg-orange-700 text-white px-4 py-2 rounded transition-colors disabled:opacity-50">
                    {createRoomMutation.isPending ? 'Creating...' : 'Create Room'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        {/* ================================================================ */}
        {/* Create Action Item Modal                                          */}
        {/* ================================================================ */}
        {showCreateAction && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 max-w-md w-full">
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-xl font-bold text-white">New Action Item</h2>
                <button onClick={() => setShowCreateAction(false)} className="text-gray-400 hover:text-white transition-colors">
                  <X className="w-5 h-5" />
                </button>
              </div>

              {createError && (
                <div className="bg-red-900/30 border border-red-700 rounded p-3 text-sm text-red-300 mb-4">{createError}</div>
              )}

              <form className="space-y-4" onSubmit={(e) => {
                e.preventDefault();
                setCreateError(null);
                const fd = new FormData(e.currentTarget);
                const roomId = fd.get('room_id') as string;
                if (!roomId) {
                  setCreateError('Please select a war room');
                  return;
                }
                createActionMutation.mutate({
                  roomId,
                  title: fd.get('title') as string,
                  priority: (fd.get('priority') as string) || 'medium',
                  description: (fd.get('description') as string) || '',
                });
              }}>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">War Room</label>
                  <select name="room_id" required className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white">
                    <option value="">Select a war room...</option>
                    {activeRooms.map((r) => (<option key={r.id} value={r.id}>{r.name}</option>))}
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Title</label>
                  <input name="title" required type="text" className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white placeholder-gray-500" placeholder="Action item description" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Description</label>
                  <textarea name="description" rows={2} className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white placeholder-gray-500 resize-none" placeholder="Additional details..." />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Priority</label>
                  <select name="priority" className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white">
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium" selected>Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
                <div className="flex gap-4 mt-6">
                  <button type="button" onClick={() => setShowCreateAction(false)} className="flex-1 bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded transition-colors">Cancel</button>
                  <button type="submit" disabled={createActionMutation.isPending} className="flex-1 bg-orange-600 hover:bg-orange-700 text-white px-4 py-2 rounded transition-colors disabled:opacity-50">
                    {createActionMutation.isPending ? 'Creating...' : 'Create'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
