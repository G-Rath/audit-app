#!/usr/bin/env node

import { auditApp } from './index';
import { parseArgs } from './parseArgs';

auditApp(parseArgs(process.argv)).catch(console.error);
