'use client';

import React, { useState } from 'react';
import {
  ShieldOff,
  FileWarning,
  Lock,
  Search,
  AlertTriangle,
  Clock,
  Eye,
  BlockIcon,
  X,
  CheckCircle,
  Edit2,
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import clsx from 'clsx';
import { dlpApi } from '../api/endpoints';

export default DLPDashboard;
