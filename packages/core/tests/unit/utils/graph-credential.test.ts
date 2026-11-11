import { describe, expect, it } from 'vitest';
import { describe_graph_credential_problem, pick_graph_credential } from '@/utils/graph-credential';
import { merge_and_validate } from '@/utils/config';

const SHARED = {
  tenant_id: 't',
  client_id: 'c',
  s3_endpoint: 'http://s3',
  s3_access_key: 'a',
  s3_secret_key: 'k',
  encryption_passphrase: 'p',
};

describe('describe_graph_credential_problem', () => {
  it('accepts a secret or a certificate alone', () => {
    expect(describe_graph_credential_problem({ client_secret: 's' })).toBeNull();
    expect(describe_graph_credential_problem({ client_certificate_path: '/c.pem' })).toBeNull();
    expect(
      describe_graph_credential_problem({
        client_certificate_path: '/c.pem',
        client_certificate_password: 'pw',
      }),
    ).toBeNull();
  });

  it('rejects both, neither, and a password without a certificate', () => {
    expect(
      describe_graph_credential_problem({ client_secret: 's', client_certificate_path: '/c.pem' }),
    ).toMatch(/not both/);
    expect(describe_graph_credential_problem({})).toMatch(/no Graph credential/);
    expect(
      describe_graph_credential_problem({ client_secret: 's', client_certificate_password: 'pw' }),
    ).toMatch(/requires a client certificate path/);
  });
});

describe('pick_graph_credential', () => {
  it('keeps only the fields that are set', () => {
    expect(pick_graph_credential({ client_certificate_path: '/c.pem', client_secret: '' })).toEqual(
      { client_certificate_path: '/c.pem' },
    );
  });
});

describe('merge_and_validate with certificates', () => {
  it('accepts a certificate in place of a secret', () => {
    const config = merge_and_validate({ ...SHARED, client_certificate_path: '/c.pem' });
    expect(config.client_certificate_path).toBe('/c.pem');
    expect(config.client_secret).toBeUndefined();
  });

  it('reports a missing credential', () => {
    expect(() => merge_and_validate(SHARED)).toThrow(/client_secret or client_certificate_path/);
  });

  it('rejects a secret together with a certificate', () => {
    expect(() =>
      merge_and_validate({ ...SHARED, client_secret: 's', client_certificate_path: '/c.pem' }),
    ).toThrow(/not both/);
  });
});
