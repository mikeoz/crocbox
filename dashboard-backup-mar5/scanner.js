/**
 * scanner.js — CROCbox Skill Scanner Engine
 *
 * Static analysis of OpenClaw skills for 5 risk categories:
 *   1. Outbound network calls
 *   2. Shell command execution
 *   3. File system access outside sandbox
 *   4. Known malware patterns
 *   5. Prompt injection indicators
 *
 * Plus detection of obfuscated code (Base64, eval of dynamic strings).
 *
 * Produces a CARD trust score (0–100) with Green/Yellow/Red/Black classification.
 *
 * Node built-ins only (fs, path).
 */

const fs = require('fs');
const path = require('path');

// ── Approved endpoints (not flagged as outbound network calls) ────────
const APPROVED_HOSTS = [
  'api.anthropic.com',
  'api.openai.com',
  'api.deepseek.com',
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  'ollama',                    // local model
];

// ── Malware Signature Database ───────────────────────────────────────
// Seeded from Cisco Talos findings + documented "What Would Elon Do" skill
const MALWARE_SIGNATURES = [
  {
    id: 'TALOS-001',
    name: 'Data exfiltration via encoded POST',
    pattern: /btoa\s*\([^)]*\)\s*.*fetch\s*\(/s,
    description: 'Base64-encodes data then sends via fetch — known exfiltration pattern',
  },
  {
    id: 'TALOS-002',
    name: 'Recursive file deletion',
    pattern: /rm\s+-rf\s+[\/~]/,
    description: 'Attempts recursive deletion of system or home directories',
  },
  {
    id: 'TALOS-003',
    name: 'SSH key exfiltration',
    pattern: /\.ssh\/(id_rsa|id_ed25519|authorized_keys)/,
    description: 'Accesses SSH private keys or authorized_keys file',
  },
  {
    id: 'TALOS-004',
    name: 'Credential harvesting',
    pattern: /(\/etc\/shadow|\/etc\/passwd).*(?:fetch|http|request|send)/s,
    description: 'Reads system credential files and transmits them',
  },
  {
    id: 'TALOS-005',
    name: 'Reverse shell',
    pattern: /(?:bash\s+-i\s+>&|nc\s+-e\s+\/bin|python.*socket.*connect|\/dev\/tcp\/)/,
    description: 'Establishes a reverse shell connection',
  },
  {
    id: 'TALOS-006',
    name: 'Crypto miner installation',
    pattern: /(?:xmrig|minergate|coinhive|cryptonight|stratum\+tcp)/i,
    description: 'Installs or connects to cryptocurrency mining software',
  },
  {
    id: 'WWED-001',
    name: '"What Would Elon Do" malware skill',
    pattern: /what\s*would\s*elon\s*do/i,
    description: 'Known malicious skill documented in OpenClaw security advisories',
  },
  {
    id: 'TALOS-007',
    name: 'Environment variable exfiltration',
    pattern: /process\.env\b.*(?:fetch|http|request|XMLHttpRequest|sendBeacon)/s,
    description: 'Reads environment variables (API keys, secrets) and transmits them',
  },
];

// ── Risk Pattern Definitions ─────────────────────────────────────────

/**
 * Category 1: Outbound network calls
 * Flags HTTP/HTTPS requests, WebSocket connections, DNS lookups
 * to endpoints not on the approved list.
 */
const NETWORK_PATTERNS = [
  { regex: /https?:\/\/([a-zA-Z0-9.-]+)/g,               extract: 'url' },
  { regex: /fetch\s*\(\s*['"`]([^'"`\s]+)/g,              extract: 'arg' },
  { regex: /axios\s*\.\s*(?:get|post|put|delete|patch|request)\s*\(\s*['"`]([^'"`\s]+)/g, extract: 'arg' },
  { regex: /require\s*\(\s*['"]https?['"]\s*\)/g,         extract: 'module' },
  { regex: /new\s+WebSocket\s*\(\s*['"`]([^'"`\s]+)/g,    extract: 'arg' },
  { regex: /XMLHttpRequest|\.open\s*\(\s*['"](?:GET|POST|PUT|DELETE)/gi, extract: 'presence' },
  { regex: /dns\.(?:lookup|resolve|resolve4|resolve6)\s*\(/g, extract: 'presence' },
  { regex: /net\.connect|net\.createConnection/g,          extract: 'presence' },
  { regex: /dgram\.createSocket/g,                         extract: 'presence' },
];

/**
 * Category 2: Shell command execution
 */
const SHELL_PATTERNS = [
  { regex: /child_process/g,                               label: 'child_process import' },
  { regex: /\bexec\s*\(\s*['"`]/g,                         label: 'exec() call' },
  { regex: /\bexecSync\s*\(/g,                             label: 'execSync() call' },
  { regex: /\bspawn\s*\(\s*['"`]/g,                        label: 'spawn() call' },
  { regex: /\bspawnSync\s*\(/g,                            label: 'spawnSync() call' },
  { regex: /\bexecFile\s*\(/g,                             label: 'execFile() call' },
  { regex: /\beval\s*\(/g,                                 label: 'eval() — dynamic execution' },
  { regex: /new\s+Function\s*\(/g,                         label: 'new Function() — dynamic execution' },
  { regex: /child_process\s*\.\s*(?:exec|spawn|fork)/g,    label: 'child_process method call' },
  { regex: /require\s*\(\s*['"]child_process['"]\s*\)/g,   label: 'child_process require' },
];

/**
 * Category 3: File system access outside sandbox
 */
const FS_PATTERNS = [
  { regex: /(?:readFile|readFileSync|createReadStream)\s*\(\s*['"`](\/[^'"`]+)/g, extract: 'path' },
  { regex: /(?:writeFile|writeFileSync|createWriteStream|appendFile)\s*\(\s*['"`](\/[^'"`]+)/g, extract: 'path' },
  { regex: /(?:readFile|readFileSync|createReadStream)\s*\(\s*['"`](~[^'"`]+)/g, extract: 'path' },
  { regex: /(?:writeFile|writeFileSync|createWriteStream|appendFile)\s*\(\s*['"`](~[^'"`]+)/g, extract: 'path' },
  { regex: /(?:\/etc\/passwd|\/etc\/shadow|\/etc\/hosts)/g, extract: 'system_file' },
  { regex: /(?:~\/\.ssh|~\/\.gnupg|~\/\.aws|~\/\.config)/g, extract: 'sensitive_dir' },
  { regex: /(?:\/var\/log|\/tmp\/.+|\/dev\/)/g,            extract: 'system_path' },
  { regex: /process\.env\.HOME|os\.homedir\(\)/g,          extract: 'home_access' },
];

/**
 * Category 5: Prompt injection indicators
 */
const INJECTION_PATTERNS = [
  { regex: /ignore\s+(?:all\s+)?previous\s+instructions/gi,  label: 'Instruction override' },
  { regex: /you\s+are\s+now\s+(?:a|an)\s+/gi,                label: 'Identity override' },
  { regex: /system\s*prompt\s*(?:override|manipulation|injection)/gi, label: 'System prompt manipulation' },
  { regex: /forget\s+(?:all\s+)?(?:your|previous)\s+(?:instructions|rules|constraints)/gi, label: 'Instruction erasure' },
  { regex: /disregard\s+(?:all\s+)?(?:previous|prior|above)/gi, label: 'Instruction disregard' },
  { regex: /\bDAN\b.*\bjailbreak/gi,                         label: 'Known jailbreak pattern (DAN)' },
  { regex: /pretend\s+(?:you\s+are|to\s+be)\s+(?:an?\s+)?(?:unrestricted|unfiltered)/gi, label: 'Restriction bypass' },
  { regex: /ADMIN_OVERRIDE|SUDO_MODE|GOD_MODE/g,             label: 'Privilege escalation string' },
];

/**
 * Category 6 (bonus): Obfuscated code
 */
const OBFUSCATION_PATTERNS = [
  { regex: /atob\s*\(\s*['"][A-Za-z0-9+\/=]{20,}['"]\s*\)/g,    label: 'Base64 decode of long string' },
  { regex: /Buffer\.from\s*\(\s*['"][A-Za-z0-9+\/=]{20,}['"]\s*,\s*['"]base64['"]\)/g, label: 'Base64 buffer decode' },
  { regex: /eval\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent)/g, label: 'eval() of decoded content' },
  { regex: /String\.fromCharCode\s*\(\s*\d+\s*(?:,\s*\d+\s*){5,}\)/g, label: 'String built from char codes' },
  { regex: /\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){5,}/gi,           label: 'Hex-encoded string sequence' },
];


// ── Penalty Schedule (from PM Spec) ─────────────────────────────────
const PENALTIES = {
  network:      { per: 20, max: 40 },
  shell:        { per: 30, max: 50 },
  filesystem:   { per: 25, max: 50 },
  malware:      { flat: 100 },          // automatic zero
  injection:    { per: 30, max: 50 },
  obfuscation:  { per: 15, max: 30 },
};


// ── Scanner Engine ───────────────────────────────────────────────────

/**
 * Scan a skill directory or single file.
 *
 * @param {string} skillPath — Path to skill directory or single .js/.ts/.py file
 * @returns {object} Scan result with score, classification, findings
 */
function scanSkill(skillPath) {
  const startTime = Date.now();

  // Resolve the path
  const resolvedPath = path.resolve(skillPath);

  if (!fs.existsSync(resolvedPath)) {
    return { error: `Path not found: ${skillPath}` };
  }

  // Collect all source files
  const stats = fs.statSync(resolvedPath);
  let files;
  if (stats.isDirectory()) {
    files = collectSourceFiles(resolvedPath);
  } else {
    files = [resolvedPath];
  }

  // Read and concatenate all source code
  let totalLines = 0;
  let allCode = '';
  const fileList = [];

  for (const filePath of files) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const lineCount = content.split('\n').length;
      totalLines += lineCount;
      allCode += '\n' + content;
      fileList.push({ path: path.relative(resolvedPath, filePath) || path.basename(filePath), lines: lineCount });
    } catch (err) {
      // Skip unreadable files
    }
  }

  // Run all scans
  const findings = [];

  // 1. Malware signatures (check first — if found, score is 0)
  const malwareHits = scanMalware(allCode);
  findings.push(...malwareHits);

  // 2. Network calls
  const networkHits = scanNetwork(allCode);
  findings.push(...networkHits);

  // 3. Shell execution
  const shellHits = scanShell(allCode);
  findings.push(...shellHits);

  // 4. File system access
  const fsHits = scanFilesystem(allCode);
  findings.push(...fsHits);

  // 5. Prompt injection
  const injectionHits = scanInjection(allCode);
  findings.push(...injectionHits);

  // 6. Obfuscation
  const obfuscationHits = scanObfuscation(allCode);
  findings.push(...obfuscationHits);

  // Calculate score
  const hasMalware = malwareHits.length > 0;
  let score = 100;

  if (hasMalware) {
    score = 0;
  } else {
    score -= Math.min(networkHits.length * PENALTIES.network.per, PENALTIES.network.max);
    score -= Math.min(shellHits.length * PENALTIES.shell.per, PENALTIES.shell.max);
    score -= Math.min(fsHits.length * PENALTIES.filesystem.per, PENALTIES.filesystem.max);
    score -= Math.min(injectionHits.length * PENALTIES.injection.per, PENALTIES.injection.max);
    score -= Math.min(obfuscationHits.length * PENALTIES.obfuscation.per, PENALTIES.obfuscation.max);
    score = Math.max(score, 0);
  }

  // Classification
  let classification, classLabel;
  if (hasMalware) {
    classification = 'black';
    classLabel = 'MALWARE DETECTED';
  } else if (score >= 80) {
    classification = 'green';
    classLabel = 'Low risk';
  } else if (score >= 50) {
    classification = 'yellow';
    classLabel = 'Medium risk';
  } else {
    classification = 'red';
    classLabel = 'High risk';
  }

  const elapsed = Date.now() - startTime;

  // Determine skill name from directory or file name
  const skillName = stats.isDirectory()
    ? path.basename(resolvedPath)
    : path.basename(resolvedPath, path.extname(resolvedPath));

  return {
    skillName,
    skillPath: resolvedPath,
    score,
    classification,
    classLabel,
    blocked: hasMalware,
    totalFiles: fileList.length,
    totalLines,
    scanTimeMs: elapsed,
    files: fileList,
    findings,
    summary: buildSummary(findings),
  };
}

/**
 * Collect all scannable source files from a directory.
 * Scans .js, .ts, .py, .mjs, .cjs, .jsx, .tsx, .sh, .bash, .yaml, .yml, .json, .md
 */
function collectSourceFiles(dirPath, maxDepth = 5, depth = 0) {
  if (depth > maxDepth) return [];

  const SCAN_EXTENSIONS = new Set([
    '.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx',
    '.py', '.sh', '.bash',
    '.yaml', '.yml', '.json', '.md',
  ]);

  const SKIP_DIRS = new Set(['node_modules', '.git', '.svn', 'dist', 'build', '.next']);

  const results = [];

  try {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) {
          results.push(...collectSourceFiles(fullPath, maxDepth, depth + 1));
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (SCAN_EXTENSIONS.has(ext)) {
          results.push(fullPath);
        }
      }
    }
  } catch (err) {
    // Skip unreadable directories
  }

  return results;
}


// ── Individual Scanners ──────────────────────────────────────────────

function scanMalware(code) {
  const hits = [];
  for (const sig of MALWARE_SIGNATURES) {
    if (sig.pattern.test(code)) {
      hits.push({
        category: 'malware',
        severity: 'critical',
        id: sig.id,
        name: sig.name,
        description: sig.description,
        icon: '✗',
      });
    }
    // Reset regex lastIndex for global patterns
    sig.pattern.lastIndex = 0;
  }
  return hits;
}

function scanNetwork(code) {
  const hits = [];
  const seen = new Set();

  for (const pat of NETWORK_PATTERNS) {
    let match;
    // Reset regex
    pat.regex.lastIndex = 0;

    while ((match = pat.regex.exec(code)) !== null) {
      let endpoint = match[1] || match[0];

      // Extract hostname if it's a URL
      try {
        if (endpoint.startsWith('http')) {
          const u = new URL(endpoint);
          endpoint = u.hostname;
        }
      } catch {}

      // Check if it's an approved host
      const isApproved = APPROVED_HOSTS.some(h =>
        endpoint === h || endpoint.endsWith('.' + h)
      );

      if (!isApproved && !seen.has(endpoint)) {
        seen.add(endpoint);
        hits.push({
          category: 'network',
          severity: 'warning',
          name: 'Outbound network call',
          description: `Network call to: ${endpoint}`,
          target: endpoint,
          icon: '⚠',
        });
      }
    }
  }
  return hits;
}

function scanShell(code) {
  const hits = [];
  const seen = new Set();

  for (const pat of SHELL_PATTERNS) {
    pat.regex.lastIndex = 0;
    if (pat.regex.test(code) && !seen.has(pat.label)) {
      seen.add(pat.label);
      hits.push({
        category: 'shell',
        severity: 'warning',
        name: 'Shell command execution',
        description: pat.label,
        icon: '⚠',
      });
    }
    pat.regex.lastIndex = 0;
  }
  return hits;
}

function scanFilesystem(code) {
  const hits = [];
  const seen = new Set();

  for (const pat of FS_PATTERNS) {
    let match;
    pat.regex.lastIndex = 0;

    while ((match = pat.regex.exec(code)) !== null) {
      const target = match[1] || match[0];
      if (!seen.has(target)) {
        seen.add(target);
        hits.push({
          category: 'filesystem',
          severity: 'warning',
          name: 'File system access outside sandbox',
          description: `Access to: ${target}`,
          target,
          icon: '⚠',
        });
      }
    }
  }
  return hits;
}

function scanInjection(code) {
  const hits = [];
  const seen = new Set();

  for (const pat of INJECTION_PATTERNS) {
    pat.regex.lastIndex = 0;
    if (pat.regex.test(code) && !seen.has(pat.label)) {
      seen.add(pat.label);
      hits.push({
        category: 'injection',
        severity: 'warning',
        name: 'Prompt injection pattern',
        description: pat.label,
        icon: '⚠',
      });
    }
    pat.regex.lastIndex = 0;
  }
  return hits;
}

function scanObfuscation(code) {
  const hits = [];
  const seen = new Set();

  for (const pat of OBFUSCATION_PATTERNS) {
    pat.regex.lastIndex = 0;
    if (pat.regex.test(code) && !seen.has(pat.label)) {
      seen.add(pat.label);
      hits.push({
        category: 'obfuscation',
        severity: 'info',
        name: 'Obfuscated code',
        description: pat.label,
        icon: '⚠',
      });
    }
    pat.regex.lastIndex = 0;
  }
  return hits;
}


// ── Summary builder ──────────────────────────────────────────────────

function buildSummary(findings) {
  const cats = {
    malware:     { found: false, count: 0, label: 'malware signatures' },
    network:     { found: false, count: 0, label: 'outbound network calls' },
    shell:       { found: false, count: 0, label: 'shell command execution' },
    filesystem:  { found: false, count: 0, label: 'file system access outside sandbox' },
    injection:   { found: false, count: 0, label: 'prompt injection patterns' },
    obfuscation: { found: false, count: 0, label: 'obfuscated code' },
  };

  for (const f of findings) {
    if (cats[f.category]) {
      cats[f.category].found = true;
      cats[f.category].count++;
    }
  }

  return Object.entries(cats).map(([key, val]) => ({
    category: key,
    label: val.label,
    found: val.found,
    count: val.count,
    icon: val.found ? (key === 'malware' ? '✗' : '⚠') : '✓',
    status: val.found
      ? (key === 'malware' ? 'DETECTED' : `${val.count} found`)
      : 'None detected',
  }));
}


module.exports = {
  scanSkill,
  MALWARE_SIGNATURES,
  APPROVED_HOSTS,
};
