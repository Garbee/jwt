import fs from 'fs/promises';
import {resolve} from 'path';

const targetPath = process.argv[2];

if (!targetPath) {
  console.error('Error: No path provided. Usage: node delete.js <path-to-delete>');
  process.exit(1);
}

const absolutePath = resolve(targetPath);

// Restrict deletions to this project directory or it's children.
const allowedBasePath = resolve(import.meta.dirname, '..');
if (!absolutePath.startsWith(allowedBasePath)) {
  console.error(`Error: Path "${absolutePath}" is outside the allowed directory.`);
  process.exit(1);
}

try {
  await fs.rm(targetPath, { recursive: true, force: true });
  console.log(`${absolutePath} deleted successfully.`);
} catch (err) {
  console.error(`Error deleting ${absolutePath}:`, err);
}
