'use client';

import React, { useState } from 'react';
import {
  Cpu,
  Factory,
  Layers,
  ShieldAlert,
  Zap,
  AlertTriangle,
  Clock,
  CheckCircle,
  X,
  Activity,
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Line,
} from 'recharts';
import clsx from 'clsx';
import { otsecurityApi } from '../api/endpoints';

export default OTSecurityDashboard;
