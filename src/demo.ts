import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

/** Values are assembled at runtime so this repository never contains anything shaped like a real key. */
const fake = {
  stripe: ['sk', 'live', 'Dem0Dem0Dem0Dem0Dem0Dem0Dem0'].join('_'),
  aws: ['AKIA', 'QYLPMN5HHHFPZAM2'].join(''),
  openai: ['sk-proj', 'Dem0abcdEFGHijklMNOPqrstUVWXyz0123456789abcd'].join('-'),
  password: ['Tr0ub4dor', '3xpl0it'].join('&'),
};

const FILES: Record<string, string> = {
  'package.json': JSON.stringify({
    name: 'demo-shop',
    version: '1.0.0',
    scripts: { dev: 'node server.js' },
    dependencies: { express: '^4.19.0', pg: '*', expresss: '^1.0.0', next: '14.0.0', react: '18.3.0' },
  }, null, 2),
  'server.js': `const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();
const stripeKey = "${fake.stripe}";
const awsKey = "${fake.aws}";
app.get('/user', (req, res) => {
  db.query(\`SELECT * FROM users WHERE id = \${req.query.id}\`);
  res.send(jwt.sign({ id: 1 }, 'super-secret-signing-key'));
});
fetch('http://localhost:4000/internal');
app.listen(3000);
`,
  '.env': `DATABASE_URL=postgres://admin:${fake.password}@db.demo-shop.io:5432/shop\nNEXT_PUBLIC_OPENAI_SECRET=${fake.openai}\n`,
  'Dockerfile': 'FROM node:latest\nCOPY . .\nRUN curl https://get.demo-shop.io/install | sh\nENV API_SECRET=abc123def456\nCMD ["node", "server.js"]\n',
  'docker-compose.yml': `services:
  db:
    image: postgres
    ports:
      - "5432:5432"
    environment:
      POSTGRES_PASSWORD: postgres
  app:
    build: .
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`,
  'supabase/migrations/001_init.sql': 'create table profiles (id uuid primary key, email text);\n',
  'backup.sql': "INSERT INTO users VALUES (1, 'ada@demo-shop.io');\n",
  'public/index.html': '<html><body><h1>Lorem ipsum</h1><a href="/login">login</a></body></html>\n',
};

/** Writes a deliberately broken project to a temporary folder and returns its path. */
export function createDemoProject(): string {
  const root = mkdtempSync(join(tmpdir(), 'alil-launch-demo-'));
  for (const [file, content] of Object.entries(FILES)) {
    const path = join(root, file);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, content);
  }
  return root;
}
