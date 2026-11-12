import { readFileSync } from 'node:fs';
import { ClientCertificateCredential, ClientSecretCredential } from '@azure/identity';
import type { TokenCredential } from '@azure/identity';
import type { GraphConfig } from '@wisecom/atlas-core/utils/config';

const PRIVATE_KEY_RE = /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/;
const CERTIFICATE_RE = /-----BEGIN CERTIFICATE-----/;

/**
 * Picks the app-only credential: a certificate when `client_certificate_path` is set, the client
 * secret otherwise. The PEM file is read here, so an unreadable file or a missing private key
 * fails at start-up with a plain message rather than as a token error on the first request.
 */
export function create_graph_credential(config: GraphConfig): TokenCredential {
  if (config.client_certificate_path === undefined) {
    return new ClientSecretCredential(config.tenant_id, config.client_id, config.client_secret!);
  }
  assert_certificate_file_usable(config.client_certificate_path);
  return new ClientCertificateCredential(config.tenant_id, config.client_id, {
    certificatePath: config.client_certificate_path,
    ...(config.client_certificate_password !== undefined
      ? { certificatePassword: config.client_certificate_password }
      : {}),
  });
}

/** Throws a descriptive error unless the file is readable PEM with a private key and a certificate. */
function assert_certificate_file_usable(path: string): void {
  let pem: string;
  try {
    pem = readFileSync(path, 'utf-8');
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code ?? 'unknown error';
    throw new Error(`Cannot read client certificate file ${path} (${code}).`);
  }
  if (!PRIVATE_KEY_RE.test(pem)) {
    throw new Error(
      `Client certificate file ${path} has no private key. Atlas needs one PEM file holding ` +
        'both the private key and the certificate.',
    );
  }
  if (!CERTIFICATE_RE.test(pem)) {
    throw new Error(`Client certificate file ${path} has no certificate (BEGIN CERTIFICATE).`);
  }
}

/**
 * Adds a hint to a token error when the cause is a certificate that the app registration does
 * not know (AADSTS700027); any other message passes through unchanged.
 */
export function describe_graph_auth_failure(err: unknown, config: GraphConfig): string {
  const message = err instanceof Error ? err.message : String(err);
  if (config.client_certificate_path !== undefined && message.includes('AADSTS700027')) {
    return (
      `${message} The certificate is not uploaded to the app registration: upload its public ` +
      'part under Certificates & secrets, or point Atlas at the matching private key.'
    );
  }
  return message;
}
