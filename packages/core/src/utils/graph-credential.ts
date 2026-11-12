import type { GraphConfig } from '@/utils/config';

type CredentialFields = Partial<
  Pick<GraphConfig, 'client_secret' | 'client_certificate_path' | 'client_certificate_password'>
>;

/**
 * Explains why a Graph credential is unusable: none given, both a secret and a certificate given,
 * or a certificate password without a certificate. Returns null when it is valid.
 */
export function describe_graph_credential_problem(source: CredentialFields): string | null {
  const has_secret = Boolean(source.client_secret);
  const has_certificate = Boolean(source.client_certificate_path);
  if (has_secret && has_certificate) {
    return 'set either a client secret or a client certificate, not both.';
  }
  if (!has_secret && !has_certificate) {
    return 'no Graph credential: set a client secret or a client certificate path.';
  }
  if (!has_certificate && source.client_certificate_password) {
    return 'a client certificate password requires a client certificate path.';
  }
  return null;
}

/** Keeps only the credential fields that are set, so absent ones stay absent. */
export function pick_graph_credential(source: CredentialFields): CredentialFields {
  return {
    ...(source.client_secret ? { client_secret: source.client_secret } : {}),
    ...(source.client_certificate_path
      ? { client_certificate_path: source.client_certificate_path }
      : {}),
    ...(source.client_certificate_password
      ? { client_certificate_password: source.client_certificate_password }
      : {}),
  };
}
