import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';

const azure = vi.hoisted(() => ({ secret: vi.fn(), certificate: vi.fn() }));
vi.mock('@azure/identity', () => ({
  ClientSecretCredential: function (...args: unknown[]) {
    azure.secret(...args);
  },
  ClientCertificateCredential: function (...args: unknown[]) {
    azure.certificate(...args);
  },
}));

import { create_graph_credential, describe_graph_auth_failure } from '@/graph-credential';

const BASE = { tenant_id: 'tenant', client_id: 'client' };
const dir = mkdtempSync(join(tmpdir(), 'atlas-cert-'));
const write_pem = (name: string, body: string): string => {
  const path = join(dir, name);
  writeFileSync(path, body);
  return path;
};
const KEY = '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n';
const CERT = '-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n';

afterAll(() => rmSync(dir, { recursive: true, force: true }));
beforeEach(() => vi.clearAllMocks());

describe('create_graph_credential', () => {
  it('uses the client secret when no certificate is configured', () => {
    create_graph_credential({ ...BASE, client_secret: 's' });
    expect(azure.secret).toHaveBeenCalledWith('tenant', 'client', 's');
    expect(azure.certificate).not.toHaveBeenCalled();
  });

  it('uses the certificate, with its password, when a path is configured', () => {
    const path = write_pem('ok.pem', KEY + CERT);
    create_graph_credential({
      ...BASE,
      client_certificate_path: path,
      client_certificate_password: 'pw',
    });
    expect(azure.certificate).toHaveBeenCalledWith('tenant', 'client', {
      certificatePath: path,
      certificatePassword: 'pw',
    });
    expect(azure.secret).not.toHaveBeenCalled();
  });

  it('omits the password when none is configured', () => {
    const path = write_pem('nopw.pem', KEY + CERT);
    create_graph_credential({ ...BASE, client_certificate_path: path });
    expect(azure.certificate).toHaveBeenCalledWith('tenant', 'client', { certificatePath: path });
  });

  it('names an unreadable file', () => {
    const path = join(dir, 'missing.pem');
    expect(() => create_graph_credential({ ...BASE, client_certificate_path: path })).toThrow(
      /Cannot read client certificate file .*missing\.pem \(ENOENT\)/,
    );
  });

  it('rejects a file without a private key', () => {
    const path = write_pem('cert-only.pem', CERT);
    expect(() => create_graph_credential({ ...BASE, client_certificate_path: path })).toThrow(
      /has no private key/,
    );
  });

  it('rejects a file without a certificate', () => {
    const path = write_pem('key-only.pem', KEY);
    expect(() => create_graph_credential({ ...BASE, client_certificate_path: path })).toThrow(
      /has no certificate/,
    );
  });
});

describe('describe_graph_auth_failure', () => {
  const failure = new Error('AADSTS700027: Client assertion contains an invalid signature');

  it('explains AADSTS700027 for a certificate credential', () => {
    const message = describe_graph_auth_failure(failure, {
      ...BASE,
      client_certificate_path: '/x.pem',
    });
    expect(message).toContain('AADSTS700027');
    expect(message).toContain('not uploaded to the app registration');
  });

  it('leaves other errors and secret credentials unchanged', () => {
    expect(describe_graph_auth_failure(failure, { ...BASE, client_secret: 's' })).toBe(
      failure.message,
    );
    expect(
      describe_graph_auth_failure(new Error('AADSTS7000215'), {
        ...BASE,
        client_certificate_path: '/x.pem',
      }),
    ).toBe('AADSTS7000215');
  });
});
