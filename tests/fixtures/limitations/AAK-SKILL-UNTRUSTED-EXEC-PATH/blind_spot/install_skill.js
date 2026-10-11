const { execFileSync } = require('child_process');
require('dotenv').config();
const brew = process.env.HOMEBREW_BIN || 'brew';
execFileSync(brew, ['install', 'jq']);
