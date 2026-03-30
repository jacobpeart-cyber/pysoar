import React, { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Shield,
  MessageSquare,
  Users,
  Clock,
  FileText,
  Plus,
  X,
  Send,
  Pin,
  AlertTriangle,
  CheckCircle,
  User,
} from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import clsx from 'clsx';
import { collaborationApi } from '../api/endpoints';


export default function WarRoom() {
  const [activeTab, setActiveTab] = useState<'rooms' | 'actions' | 'postmortems'>('rooms');
  const [selectedRoom, setSelectedRoom] = useState<WarRoom | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [newMessage, setNewMessage] = useState('');
  const [messages, setMessages] = useState([
    { id: 1, author: 'Alice Johnson', text: 'Database node 3 is unresponsive, initiating failover', time: '13:47' },
    { id: 2, author: 'Bob Smith', text: 'Confirmed, switching to replica. ETA 5 minutes', time: '13:48' },
    { id: 3, author: 'Carol White', text: 'Monitoring DNS propagation, all clear', time: '13:49' },
  ]);

  const { data: warRooms = [] } = useQuery({ queryKey: ['warRooms'], queryFn: collaborationApi.getWarRooms });
  const { data: actionItems = [] } = useQuery({ queryKey: ['actionItems'], queryFn: collaborationApi.getActionItems });
  const { data: postMortems = [] } = useQuery({ queryKey: ['postMortems'], queryFn: collaborationApi.getPostMortems });

  const stats = useMemo(() => {
    const activeRooms = warRooms.filter((r: WarRoom) => r.status === 'Active').length;
    const myActionItems = actionItems.length;
    const overdueActions = actionItems.filter((a: ActionItem) => a.status === 'Overdue').length;
    const avgMTTR = '35m';
    return { activeRooms, myActionItems, overdueActions, avgMTTR };
  }, [warRooms, actionItems]);

  const mttrTrendData = [
    { incident: 'Cache Failure', mttd: 8, mttr: 42 },
    { incident: 'DNS Issue', mttd: 15, mttr: 25 },
    { incident: 'LB Config', mttd: 5, mttr: 18 },
    { incident: 'Avg', mttd: 9, mttr: 28 },
  ];

  const handleSendMessage = () => {
    if (newMessage.trim()) {
      setMessages([
        ...messages,
        { id: messages.length + 1, author: 'You', text: newMessage, time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) },
      ]);
      setNewMessage('');
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold mb-2 flex items-center gap-3">
            <Shield className="w-8 h-8 text-orange-400" />
            War Room
          </h1>
          <p className="text-gray-400">Incident Response Coordination & Post-Mortem Management</p>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-4 gap-4 mb-8">
          <div className={clsx('border rounded-lg p-6 dark:border-gray-700', stats.activeRooms > 0 ? 'bg-red-900/20 border-red-700' : 'bg-gray-800 border-gray-700')}>
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Active War Rooms</p>
                <p className="text-3xl font-bold">{stats.activeRooms}</p>
              </div>
              <Shield className="w-8 h-8 text-orange-400" />
            </div>
          </div>

          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">My Action Items</p>
                <p className="text-3xl font-bold">{stats.myActionItems}</p>
              </div>
              <FileText className="w-8 h-8 text-blue-400" />
            </div>
          </div>

          <div className={clsx('border rounded-lg p-6 dark:border-gray-700', stats.overdueActions > 0 ? 'bg-red-900/20 border-red-700' : 'bg-gray-800 border-gray-700')}>
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Overdue Actions</p>
                <p className="text-3xl font-bold">{stats.overdueActions}</p>
              </div>
              <AlertTriangle className="w-8 h-8 text-red-400" />
            </div>
          </div>

          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-gray-400 text-sm mb-2">Avg MTTR</p>
                <p className="text-3xl font-bold">{stats.avgMTTR}</p>
              </div>
              <Clock className="w-8 h-8 text-green-400" />
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="mb-6 border-b border-gray-700">
          <div className="flex gap-8">
            {[
              { id: 'rooms', label: 'Active War Rooms', icon: Shield },
              { id: 'actions', label: 'Action Items', icon: FileText },
              { id: 'postmortems', label: 'Post-Mortems', icon: Clock },
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

        {/* War Rooms Tab */}
        {activeTab === 'rooms' && (
          <div className="space-y-4">
            {warRooms.map((room: WarRoom) => (
              <div
                key={room.id}
                onClick={() => setSelectedRoom(room)}
                className={clsx(
                  'border rounded-lg p-6 cursor-pointer transition-colors dark:border-gray-700',
                  room.severity === 'Critical'
                    ? 'bg-red-900/20 border-red-700 hover:bg-red-900/30'
                    : 'bg-gray-800 border-gray-700 hover:bg-gray-700/50'
                )}
              >
                <div className="flex items-start justify-between mb-4">
                  <div className="flex-1">
                    <h3 className="text-lg font-semibold text-white mb-2">{room.title}</h3>
                    <div className="flex items-center gap-4 text-sm text-gray-400 mb-2">
                      <span className="flex items-center gap-1">
                        <Users className="w-4 h-4" />
                        {room.participants} participants
                      </span>
                      <span className="flex items-center gap-1">
                        <User className="w-4 h-4" />
                        Commander: {room.commander}
                      </span>
                      <span className="flex items-center gap-1">
                        <Clock className="w-4 h-4" />
                        Started: {room.startTime}
                      </span>
                    </div>
                  </div>
                  <div className="text-right">
                    <span
                      className={clsx(
                        'px-3 py-1 rounded text-xs font-medium mb-2 block',
                        room.severity === 'Critical'
                          ? 'bg-red-900/60 text-red-200'
                          : 'bg-orange-900/60 text-orange-200'
                      )}
                    >
                      {room.severity}
                    </span>
                    <span
                      className={clsx(
                        'px-3 py-1 rounded text-xs font-medium block',
                        room.status === 'Active'
                          ? 'bg-red-900/40 text-red-300'
                          : 'bg-green-900/40 text-green-300'
                      )}
                    >
                      {room.status}
                    </span>
                  </div>
                </div>

                <div className="flex items-center justify-between">
                  <span
                    className={clsx(
                      'px-3 py-1 rounded text-xs font-medium',
                      room.impact === 'Critical'
                        ? 'bg-red-900/40 text-red-300'
                        : room.impact === 'High'
                          ? 'bg-orange-900/40 text-orange-300'
                          : 'bg-yellow-900/40 text-yellow-300'
                    )}
                  >
                    Impact: {room.impact}
                  </span>
                  <button className="text-blue-400 hover:text-blue-300 text-sm font-medium transition-colors">
                    View Details →
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Action Items Tab */}
        {activeTab === 'actions' && (
          <div>
            <div className="mb-6 flex justify-end">
              <button
                onClick={() => setShowModal(true)}
                className="bg-orange-600 hover:bg-orange-700 text-white px-4 py-2 rounded flex items-center gap-2 transition-colors"
              >
                <Plus className="w-4 h-4" />
                New Action Item
              </button>
            </div>

            <div className="space-y-4">
              {actionItems.map((item: ActionItem) => (
                <div
                  key={item.id}
                  className={clsx(
                    'border rounded-lg p-6 dark:border-gray-700',
                    item.status === 'Overdue'
                      ? 'bg-red-900/20 border-red-700'
                      : item.status === 'In Progress'
                        ? 'bg-blue-900/20 border-blue-700'
                        : 'bg-gray-800 border-gray-700'
                  )}
                >
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex-1">
                      <h3 className="text-lg font-semibold text-white mb-2">{item.title}</h3>
                      <p className="text-sm text-gray-400 mb-2">Assigned to: {item.assignee}</p>
                    </div>
                    <span
                      className={clsx(
                        'px-3 py-1 rounded text-xs font-medium',
                        item.priority === 'Critical'
                          ? 'bg-red-900/60 text-red-200'
                          : item.priority === 'High'
                            ? 'bg-orange-900/60 text-orange-200'
                            : 'bg-yellow-900/60 text-yellow-200'
                      )}
                    >
                      {item.priority}
                    </span>
                  </div>

                  <div className="grid grid-cols-3 gap-4">
                    <div>
                      <p className="text-xs text-gray-400 mb-1">War Room</p>
                      <p className="text-white font-mono text-sm">{item.room}</p>
                    </div>
                    <div>
                      <p className="text-xs text-gray-400 mb-1">Due Date</p>
                      <p className="text-white text-sm">{item.dueDate}</p>
                    </div>
                    <div>
                      <p className="text-xs text-gray-400 mb-1">Status</p>
                      <span
                        className={clsx(
                          'px-2 py-1 rounded text-xs font-medium inline-block',
                          item.status === 'In Progress'
                            ? 'bg-blue-900/40 text-blue-300'
                            : item.status === 'Overdue'
                              ? 'bg-red-900/40 text-red-300'
                              : 'bg-gray-900/40 text-gray-300'
                        )}
                      >
                        {item.status}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Post-Mortems Tab */}
        {activeTab === 'postmortems' && (
          <div>
            <div className="mb-8">
              <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
                <h3 className="text-lg font-semibold mb-4">MTTD/MTTR Trends</h3>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={mttrTrendData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis dataKey="incident" stroke="#9CA3AF" />
                    <YAxis stroke="#9CA3AF" />
                    <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', borderRadius: '8px' }} />
                    <Legend />
                    <Line type="monotone" dataKey="mttd" stroke="#3B82F6" strokeWidth={2} name="MTTD (min)" />
                    <Line type="monotone" dataKey="mttr" stroke="#10B981" strokeWidth={2} name="MTTR (min)" />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="space-y-4">
              {postMortems.map((pm: PostMortem) => (
                <div key={pm.id} className="bg-gray-800 border border-gray-700 rounded-lg p-6 dark:bg-gray-800 dark:border-gray-700">
                  <div className="flex items-start justify-between mb-4">
                    <div>
                      <h3 className="text-lg font-semibold text-white mb-2">{pm.title}</h3>
                      <p className="text-sm text-gray-400">Timeline: {pm.timeline}</p>
                    </div>
                    <span
                      className={clsx(
                        'px-3 py-1 rounded text-xs font-medium',
                        pm.severity === 'High' ? 'bg-orange-900/60 text-orange-200' : 'bg-yellow-900/60 text-yellow-200'
                      )}
                    >
                      {pm.severity}
                    </span>
                  </div>

                  <div className="grid grid-cols-3 gap-4">
                    <div className="bg-gray-700/50 rounded p-3">
                      <p className="text-xs text-gray-400 mb-1">Mean Time to Detect</p>
                      <p className="text-2xl font-bold text-blue-400">{pm.mttd}</p>
                    </div>
                    <div className="bg-gray-700/50 rounded p-3">
                      <p className="text-xs text-gray-400 mb-1">Mean Time to Resolve</p>
                      <p className="text-2xl font-bold text-green-400">{pm.mttr}</p>
                    </div>
                    <div className="bg-gray-700/50 rounded p-3">
                      <p className="text-xs text-gray-400 mb-1">Mean Time to Close</p>
                      <p className="text-2xl font-bold text-purple-400">{pm.mttc}</p>
                    </div>
                  </div>

                  <button className="mt-4 text-blue-400 hover:text-blue-300 text-sm font-medium transition-colors">
                    View Full Report →
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* War Room Detail Modal */}
        {selectedRoom && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-gray-800 border border-gray-700 rounded-lg max-w-2xl w-full max-h-96 flex flex-col dark:bg-gray-800 dark:border-gray-700">
              <div className="flex items-start justify-between p-6 border-b border-gray-700">
                <div>
                  <h2 className="text-2xl font-bold text-white mb-2">{selectedRoom.title}</h2>
                  <p className="text-sm text-gray-400">Started: {selectedRoom.startTime}</p>
                </div>
                <button
                  onClick={() => setSelectedRoom(null)}
                  className="text-gray-400 hover:text-white transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="flex-1 overflow-y-auto p-6 space-y-4">
                {messages.map((msg) => (
                  <div key={msg.id} className="bg-gray-700/50 rounded-lg p-4">
                    <div className="flex items-start justify-between mb-2">
                      <p className="font-semibold text-white">{msg.author}</p>
                      <span className="text-xs text-gray-400">{msg.time}</span>
                    </div>
                    <p className="text-gray-300">{msg.text}</p>
                  </div>
                ))}
              </div>

              <div className="border-t border-gray-700 p-6 space-y-4">
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={newMessage}
                    onChange={(e) => setNewMessage(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()}
                    placeholder="Type your message..."
                    className="flex-1 bg-gray-700 border border-gray-600 rounded px-4 py-2 text-white placeholder-gray-500 dark:bg-gray-700 dark:border-gray-600"
                  />
                  <button
                    onClick={handleSendMessage}
                    className="bg-orange-600 hover:bg-orange-700 text-white px-4 py-2 rounded flex items-center gap-2 transition-colors"
                  >
                    <Send className="w-4 h-4" />
                  </button>
                </div>

                <div className="flex gap-2">
                  <button className="flex-1 bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded text-sm transition-colors flex items-center justify-center gap-2">
                    <Pin className="w-4 h-4" />
                    Pin Important
                  </button>
                  <button
                    onClick={() => setSelectedRoom(null)}
                    className="flex-1 bg-orange-600 hover:bg-orange-700 text-white px-4 py-2 rounded text-sm transition-colors"
                  >
                    Close Room
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* New Action Item Modal */}
        {showModal && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 max-w-md w-full dark:bg-gray-800 dark:border-gray-700">
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-xl font-bold text-white">New Action Item</h2>
                <button
                  onClick={() => setShowModal(false)}
                  className="text-gray-400 hover:text-white transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Title</label>
                  <input
                    type="text"
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white placeholder-gray-500 dark:bg-gray-700 dark:border-gray-600"
                    placeholder="Action item description"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Priority</label>
                  <select className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white dark:bg-gray-700 dark:border-gray-600">
                    <option>Critical</option>
                    <option>High</option>
                    <option>Medium</option>
                  </select>
                </div>

                <div className="flex gap-4 mt-6">
                  <button
                    onClick={() => setShowModal(false)}
                    className="flex-1 bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={() => setShowModal(false)}
                    className="flex-1 bg-orange-600 hover:bg-orange-700 text-white px-4 py-2 rounded transition-colors"
                  >
                    Create
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
