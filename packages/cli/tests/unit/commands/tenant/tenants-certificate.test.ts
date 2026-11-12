import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, expect, vi, beforeEach, afterEach, afterAll } from 'vitest';
import { Command } from 'commander';
import { register_tenants_command } from '@/commands/tenant/tenants.command';

vi.mock('dotenv', () => ({ config: vi.fn() }));

const azure_mocks = vi.hoisted(() => ({ certificate: vi.fn(), get_token: vi.fn() }));
vi.mock('@azure/identity', () => ({
  ClientSecretCredential: function () {
    return { getToken: azure_mocks.get_token };
  },
  ClientCertificateCredential: function (...args: unknown[]) {
    azure_mocks.certificate(...args);
    return { getToken: azure_mocks.get_token };
  },
}));

const mocks = vi.hoisted(() => {
  const write_secure_config = vi.fn();
  return {
    write_secure_config,
    read_secure_config: vi.fn(() => ({})),
    update_secure_config: vi.fn((mutate: (current: object) => object) => {
      const next = mutate({});
      write_secure_config(next);
      return next;
    }),
    read_env_overrides: vi.fn(() => ({})),
    try_load_config_file: vi.fn(() => ({})),
    secure_config_dir: vi.fn(() => '/tmp/fake-atlas'),
  };
});
vi.mock('@wisecom/atlas-core', async (import_original) => ({
  ...(await import_original<Record<string, unknown>>()),
  ...mocks,
}));

const TENANT = '00000000-0000-0000-0000-000000000001';
const CLIENT = '00000000-0000-0000-0000-000000000002';
const dir = mkdtempSync(join(tmpdir(), 'atlas-cert-cli-'));
const pem = join(dir, 'app.pem');
writeFileSync(
  pem,
  '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n' +
    '-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n',
);

let output: string[];

function run(args: string[]): Promise<unknown> {
  const program = new Command();
  program.exitOverride();
  register_tenants_command(program);
  return program.parseAsync(['tenants', ...args], { from: 'user' });
}

const base = ['add', 'work', '--tenant-id', TENANT, '--client-id', CLIENT];

beforeEach(() => {
  vi.clearAllMocks();
  mocks.read_env_overrides.mockReturnValue({});
  mocks.read_secure_config.mockReturnValue({});
  output = [];
  const capture = (...parts: unknown[]): void => {
    output.push(parts.map(String).join(' '));
  };
  for (const level of ['log', 'info', 'warn', 'error'] as const) {
    vi.spyOn(console, level).mockImplementation(capture);
  }
  azure_mocks.get_token.mockResolvedValue({ token: 'fake' });
  process.exitCode = undefined;
});

afterEach(() => {
  vi.restoreAllMocks();
  process.exitCode = undefined;
});

afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe('atlas tenants add --client-certificate', () => {
  it('stores the certificate path and password, and probes with the certificate', async () => {
    await run([...base, '--client-certificate', pem, '--client-certificate-password', 'pw']);

    expect(mocks.write_secure_config).toHaveBeenCalledWith({
      tenants: {
        work: {
          tenant_id: TENANT,
          client_id: CLIENT,
          client_certificate_path: pem,
          client_certificate_password: 'pw',
        },
      },
      active_tenant: 'work',
    });
    expect(azure_mocks.certificate).toHaveBeenCalledWith(TENANT, CLIENT, {
      certificatePath: pem,
      certificatePassword: 'pw',
    });
    expect(process.exitCode).toBeUndefined();
  });

  it('refuses a secret together with a certificate, before any write', async () => {
    await expect(
      run([...base, '--client-secret', 's', '--client-certificate', pem]),
    ).rejects.toThrow(/not both/);
    expect(mocks.write_secure_config).not.toHaveBeenCalled();
  });

  it('refuses to add a profile with no credential', async () => {
    await expect(run(base)).rejects.toThrow(/no Graph credential/);
    expect(mocks.write_secure_config).not.toHaveBeenCalled();
  });

  it('reports a certificate the app registration rejects, with a hint', async () => {
    azure_mocks.get_token.mockRejectedValue(new Error('AADSTS700027: invalid signature'));

    await run([...base, '--client-certificate', pem]);

    expect(process.exitCode).toBe(1);
    expect(output.join('\n')).toMatch(/not uploaded to the app registration/);
  });

  it('reports an unreadable certificate file', async () => {
    await run([...base, '--client-certificate', join(dir, 'missing.pem')]);

    expect(process.exitCode).toBe(1);
    expect(output.join('\n')).toMatch(/Cannot read client certificate file/);
  });
});

describe('atlas tenants validate with mixed credentials', () => {
  it('fails a stored secret profile when the environment adds a certificate', async () => {
    mocks.read_secure_config.mockReturnValue({
      tenants: { work: { tenant_id: TENANT, client_id: CLIENT, client_secret: 's' } },
      active_tenant: 'work',
    } as never);
    mocks.read_env_overrides.mockReturnValue({ client_certificate_path: pem } as never);

    await run(['validate']);

    expect(process.exitCode).toBe(1);
    expect(output.join('\n')).toMatch(/not both/);
    expect(azure_mocks.certificate).not.toHaveBeenCalled();
  });
});
