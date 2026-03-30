'use client';

import React, { useState } from 'react';
import {
  Workflow,
  Play,
  Pause,
  CheckCircle,
  Layout,
  Edit2,
  Copy,
  Trash2,
  Clock,
  BarChart3,
  X,
  Plus,
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import clsx from 'clsx';
import { playbookApi } from '../api/endpoints';

export default PlaybookBuilder;
