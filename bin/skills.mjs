#!/usr/bin/env node

import { existsSync, mkdirSync, readdirSync, statSync, copyFileSync, readFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';

const __filename = fileURLToPath(import.meta.url);
const DATA_ROOT = resolve(dirname(__filename), '..');
const CWD = process.cwd();
const VERSION = JSON.parse(readFileSync(join(DATA_ROOT, 'package.json'), 'utf8')).version;

const TOOLS = {
  'claude-code': {
    name: 'Claude Code',
    detect: () => existsSync(join(CWD, '.claude')),
    skillsDir: '.claude/skills',
  },
  'gemini-cli': {
    name: 'Gemini CLI',
    detect: () => existsSync(join(CWD, '.gemini')),
    skillsDir: '.gemini/skills',
  },
  cursor: {
    name: 'Cursor',
    detect: () => existsSync(join(CWD, '.cursor')) || existsSync(join(CWD, '.cursorrules')),
    skillsDir: '.cursor/rules/security-skills',
  },
  codex: {
    name: 'Codex CLI',
    detect: () => existsSync(join(CWD, '.codex')),
    skillsDir: '.codex/skills',
  },
  generic: {
    name: 'Generic (./security-skills/)',
    detect: () => true,
    skillsDir: 'security-skills',
  },
};

function copyRecursive(src, dest) {
  let count = 0;
  mkdirSync(dest, { recursive: true });
  for (const entry of readdirSync(src)) {
    const srcPath = join(src, entry);
    const destPath = join(dest, entry);
    if (statSync(srcPath).isDirectory()) {
      count += copyRecursive(srcPath, destPath);
    } else {
      copyFileSync(srcPath, destPath);
      count++;
    }
  }
  return count;
}

function prompt(question) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

function printUsage() {
  console.log(`
  @unitone/skills v${VERSION}
  45 security skills for AI coding agents

  Usage:
    npx @unitone/skills init [options]    Install skills into your project
    npx @unitone/skills list              List all available skills
    npx @unitone/skills --version         Show version
    npx @unitone/skills --help            Show this help

  Options:
    -y, --yes       Auto-detect tools and install without prompting
    --force         Overwrite existing skills directory
    --tool <name>   Install for a specific tool (claude-code, gemini-cli, cursor, codex, generic)
`);
}

function listSkills() {
  const indexPath = join(DATA_ROOT, 'index.yaml');
  const content = readFileSync(indexPath, 'utf8');
  const lines = content.split('\n');

  console.log('\n  Security Skills\n');

  // Parse skills into structured data, skip roles
  const skills = [];
  let current = null;
  let inRoles = false;
  for (const line of lines) {
    if (line.match(/^roles:/)) { inRoles = true; continue; }
    if (inRoles) continue;

    const idMatch = line.match(/^\s+-\s+id:\s+(.+)/);
    if (idMatch) {
      current = { id: idMatch[1].trim(), name: '', domain: '' };
      skills.push(current);
      continue;
    }
    if (!current) continue;
    const nameMatch = line.match(/^\s+name:\s+"([^"]+)"/);
    if (nameMatch) current.name = nameMatch[1];
    const fileMatch = line.match(/^\s+file:\s+skills\/([^/]+)\//);
    if (fileMatch) current.domain = fileMatch[1];
  }

  let currentDomain = '';
  for (const skill of skills) {
    if (!skill.domain || !skill.name) continue;
    if (skill.domain !== currentDomain) {
      currentDomain = skill.domain;
      console.log(`\n  ${currentDomain}`);
      console.log(`  ${'─'.repeat(currentDomain.length)}`);
    }
    console.log(`    ${skill.name}`);
  }
  console.log('');
}

async function init(args) {
  const autoYes = args.includes('-y') || args.includes('--yes');
  const force = args.includes('--force');
  const toolIdx = args.indexOf('--tool');
  const specificTool = toolIdx !== -1 ? args[toolIdx + 1] : null;

  console.log(`\n  @unitone/skills v${VERSION}\n`);

  let selectedKeys = [];

  if (specificTool) {
    if (!TOOLS[specificTool]) {
      console.error(`  Unknown tool: ${specificTool}`);
      console.error(`  Available: ${Object.keys(TOOLS).join(', ')}`);
      process.exit(1);
    }
    selectedKeys = [specificTool];
  } else {
    const detected = Object.entries(TOOLS)
      .filter(([key, cfg]) => key !== 'generic' && cfg.detect())
      .map(([key]) => key);

    if (autoYes) {
      selectedKeys = detected.length > 0 ? detected : ['generic'];
    } else {
      const entries = Object.entries(TOOLS);
      console.log('  Available targets:\n');
      entries.forEach(([key, cfg], i) => {
        const tag = key !== 'generic' && cfg.detect() ? ' (detected)' : '';
        console.log(`    [${i + 1}] ${cfg.name}${tag}`);
      });

      const answer = await prompt('\n  Install for which targets? (numbers, comma-separated, or "all"): ');

      if (answer.toLowerCase() === 'all') {
        selectedKeys = Object.keys(TOOLS);
      } else {
        const nums = answer.split(',').map((s) => parseInt(s.trim(), 10)).filter((n) => !isNaN(n));
        selectedKeys = nums.map((n) => entries[n - 1]?.[0]).filter(Boolean);
      }

      if (selectedKeys.length === 0) {
        console.log('  No targets selected. Exiting.\n');
        process.exit(0);
      }
    }
  }

  const skillsSrc = join(DATA_ROOT, 'skills');
  const rolesSrc = join(DATA_ROOT, 'roles');
  const indexSrc = join(DATA_ROOT, 'index.yaml');

  for (const key of selectedKeys) {
    const cfg = TOOLS[key];
    const targetDir = join(CWD, cfg.skillsDir);

    if (existsSync(targetDir) && !force) {
      const answer = autoYes ? 'y' : await prompt(`  ${targetDir} already exists. Overwrite? (y/N): `);
      if (answer.toLowerCase() !== 'y') {
        console.log(`  Skipped ${cfg.name}`);
        continue;
      }
    }

    const skillsTarget = join(targetDir, 'skills');
    const rolesTarget = join(targetDir, 'roles');
    const indexTarget = join(targetDir, 'index.yaml');

    // For claude-code and gemini, skills go directly in the skills dir
    // not nested under a subdirectory
    let sTarget, rTarget, iTarget;
    if (key === 'generic') {
      sTarget = join(targetDir, 'skills');
      rTarget = join(targetDir, 'roles');
      iTarget = join(targetDir, 'index.yaml');
    } else {
      // For tool-specific dirs, put content directly in the skills dir
      sTarget = targetDir;
      rTarget = join(dirname(targetDir), 'roles');
      iTarget = join(dirname(targetDir), 'security-index.yaml');
    }

    const fileCount = copyRecursive(skillsSrc, sTarget);
    const roleCount = copyRecursive(rolesSrc, rTarget);
    mkdirSync(dirname(iTarget), { recursive: true });
    copyFileSync(indexSrc, iTarget);

    console.log(`  ${cfg.name}`);
    console.log(`    ${fileCount} skill files  → ${sTarget}`);
    console.log(`    ${roleCount} role files   → ${rTarget}`);
    console.log(`    index.yaml       → ${iTarget}`);
    console.log('');
  }

  console.log('  Done! Try asking your AI agent:\n');
  console.log('    "Run a threat model on this project"');
  console.log('    "Review this code for security issues"');
  console.log('    "Triage CVE-2024-XXXX for our stack"');
  console.log('');
}

// --- Main ---

const args = process.argv.slice(2);
const command = args[0];

if (args.includes('--version') || args.includes('-v')) {
  console.log(VERSION);
} else if (args.includes('--help') || args.includes('-h') || !command) {
  printUsage();
} else if (command === 'init') {
  init(args.slice(1));
} else if (command === 'list') {
  listSkills();
} else {
  console.error(`  Unknown command: ${command}`);
  printUsage();
  process.exit(1);
}
