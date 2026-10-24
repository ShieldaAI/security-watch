import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from 'node:fs';
import { parseEnv } from 'node:util';

export const SYSTEM_TEMPLATES = [
  { id: 'nodejs', name: 'Node.js', keywords: ['NodeJS', 'Node.js runtime'] },
  { id: 'python', name: 'Python', keywords: ['CPython'] },
  { id: 'java', name: 'Java', keywords: ['OpenJDK', 'Java SE', 'Oracle JDK'] },
  { id: 'go', name: 'Go', keywords: ['Golang', 'Go runtime', 'Go standard library'] },
  { id: 'rust', name: 'Rust', keywords: ['rustc', 'Cargo'] },
  { id: 'php', name: 'PHP', keywords: [] },
  { id: 'ruby', name: 'Ruby', keywords: ['Ruby on Rails'] },
  { id: 'dotnet', name: '.NET', keywords: ['ASP.NET', '.NET Core'] },
  { id: 'linux', name: 'Linux', keywords: ['Linux kernel'] },
  { id: 'windows', name: 'Windows', keywords: ['Windows Server'] },
  { id: 'docker', name: 'Docker', keywords: ['Docker Engine', 'Docker Desktop', 'Moby'] },
  { id: 'kubernetes', name: 'Kubernetes', keywords: ['kubelet', 'kube-apiserver'] },
  { id: 'nginx', name: 'NGINX', keywords: [] },
  { id: 'apache-http', name: 'Apache HTTP Server', keywords: ['Apache httpd'] },
  { id: 'openssl', name: 'OpenSSL', keywords: [] },
  { id: 'openssh', name: 'OpenSSH', keywords: [] },
  { id: 'postgresql', name: 'PostgreSQL', keywords: ['Postgres'] },
  { id: 'mysql', name: 'MySQL', keywords: [] },
  { id: 'redis', name: 'Redis', keywords: [] },
  { id: 'mongodb', name: 'MongoDB', keywords: [] },
  { id: 'git', name: 'Git', keywords: [] },
  { id: 'jenkins', name: 'Jenkins', keywords: [] },
  { id: 'elasticsearch', name: 'Elasticsearch', keywords: [] },
  { id: 'sqlite', name: 'SQLite', keywords: [] },
] as const;

export function starterSystems(selection: string, now = Date.now()) {
  const ids = selection.split(',').map((id) => id.trim());
  if (!ids.length || ids.some((id) => !SYSTEM_TEMPLATES.some((template) => template.id === id)))
    throw new Error('Unknown system template. Run security-watch templates for the available names.');
  return [...new Set(ids)].map((id) => {
    const template = SYSTEM_TEMPLATES.find((entry) => entry.id === id)!;
    return {
      id: template.id,
      name: template.name,
      environment: 'unknown',
      exposure: 'unknown',
      criticality: 'unknown',
      updated_at: new Date(now).toISOString(),
      components: [],
      products: [{ name: template.name, keywords: [...template.keywords] }],
      keywords: [],
    };
  });
}

/** Load dotenv data only when requested. Existing environment values take precedence. */
export function loadEnvFile(path: string): void {
  let fd: number;
  try {
    if (!lstatSync(path).isFile()) throw new Error('Not a regular file');
    fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  } catch {
    throw new Error('Cannot open the env file. Use a regular private file.');
  }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > 131_072)
      throw new Error('The env file must be a regular file no larger than 128 KiB.');
    if (process.platform !== 'win32' && (stat.mode & 0o077) !== 0)
      throw new Error('The env file is readable by other users. Run chmod 600 on it first.');
    const buffer = Buffer.alloc(131_073);
    let size = 0;
    while (size < buffer.length) {
      const count = readSync(fd, buffer, size, buffer.length - size, null);
      if (!count) break;
      size += count;
    }
    if (size > 131_072) throw new Error('The env file exceeds 128 KiB.');
    const text = buffer.toString('utf8', 0, size);
    const values = parseEnv(text);
    if (
      Object.keys(values)
        .map((name) => name.toUpperCase())
        .some(
          (name) =>
            /^(LD_|DYLD_)/.test(name) ||
            [
              'PATH',
              'HOME',
              'SHELL',
              'NODE_OPTIONS',
              'NODE_TLS_REJECT_UNAUTHORIZED',
              'NODE_EXTRA_CA_CERTS',
              'NODE_USE_SYSTEM_CA',
              'NODE_USE_ENV_PROXY',
              'SSL_CERT_FILE',
              'SSL_CERT_DIR',
            ].includes(name),
        )
    )
      throw new Error(
        'Use the env file for application settings and credentials, not shell or TLS runtime settings.',
      );
    for (const [name, value] of Object.entries(values))
      if (process.env[name] === undefined) process.env[name] = value;
  } finally {
    closeSync(fd);
  }
}
