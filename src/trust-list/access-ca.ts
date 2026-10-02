import 'reflect-metadata'
import { randomBytes, webcrypto } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import * as x509 from '@peculiar/x509'
import { DATA_DIR, writeDataFile } from '../common/keys.js'
import { ETSI119411_8 } from './etsi119602.js'

x509.cryptoProvider.set(webcrypto as unknown as Crypto)

const EC = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' } as const
const OID_ORGANIZATION_IDENTIFIER = '2.5.4.97'
const OID_ANY_POLICY = '2.5.29.32.0'

export type IssuedCertificate = {
  serial: string
  clientId: string
  subject: string
  notBefore: string
  notAfter: string
  revoked?: { at: string; reason: x509.X509CrlReason }
}

export type WrpacRequest = {
  clientId: string
  /** dNSName used by the x509_san_dns Client Identifier Prefix (OpenID4VP). */
  dnsName: string
  /** Legal person: organizationName / organizationIdentifier (EN 319 412-1) / commonName. */
  organizationName: string
  organizationIdentifier: string
  commonName: string
  country: string
  /** Contact information required in subjectAltName (TS 119 411-8 clause 6.6.1). */
  contactUri: string
  publicKey: CryptoKey
}

const toPem = (label: string, der: ArrayBuffer) =>
  `-----BEGIN ${label}-----\n${Buffer.from(der).toString('base64').match(/.{1,64}/g)?.join('\n')}\n-----END ${label}-----\n`

/** Self-signed certificate for a key (used for the LoTE scheme operator signing certificate). */
export const selfSignedCertificate = async (opts: {
  name: string
  privateKey: CryptoKey
  publicKey: CryptoKey
  years?: number
}) =>
  x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: `01${randomBytes(15).toString('hex')}`,
    name: opts.name,
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + (opts.years ?? 3) * 365 * 24 * 3600 * 1000),
    signingAlgorithm: EC,
    keys: { privateKey: opts.privateKey, publicKey: opts.publicKey },
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      await x509.SubjectKeyIdentifierExtension.create(opts.publicKey),
    ],
  })

/**
 * Access Certificate Authority (WRPAC Provider). Issues Wallet-Relying Party Access Certificates
 * following the ETSI TS 119 411-8 profile (legal person, NCP-l-eudiwrp) and publishes a CRL
 * (RFC 5280) used by Wallet Units for revocation checking.
 */
export const createAccessCa = async (opts: { baseUrl: string; name: string; country: string; organizationIdentifier: string }) => {
  const dir = join(DATA_DIR, 'trust-list')
  const keyPath = join(dir, 'access-ca-key.pem')
  const certPath = join(dir, 'access-ca-cert.pem')
  const statePath = join(dir, 'access-ca-issued.json')
  const crlUri = `${opts.baseUrl}/ca/crl`
  const caIssuersUri = `${opts.baseUrl}/ca/cert`

  let caKeys: CryptoKeyPair
  let caCert: x509.X509Certificate
  if (existsSync(keyPath) && existsSync(certPath)) {
    caCert = new x509.X509Certificate(readFileSync(certPath, 'utf-8'))
    const pkcs8 = x509.PemConverter.decodeFirst(readFileSync(keyPath, 'utf-8'))
    caKeys = {
      privateKey: await webcrypto.subtle.importKey('pkcs8', pkcs8, EC, true, ['sign']),
      publicKey: await caCert.publicKey.export(EC, ['verify']),
    } as CryptoKeyPair
  } else {
    caKeys = (await webcrypto.subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair
    caCert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: `01${randomBytes(15).toString('hex')}`,
      name: `C=${opts.country}, O=${opts.name}, ${OID_ORGANIZATION_IDENTIFIER}=${opts.organizationIdentifier}, CN=${opts.name} WRP Access CA`,
      notBefore: new Date(Date.now() - 60_000),
      notAfter: new Date(Date.now() + 5 * 365 * 24 * 3600 * 1000),
      signingAlgorithm: EC,
      keys: caKeys,
      extensions: [
        // pathLen 0: this CA only issues end-entity access certificates
        new x509.BasicConstraintsExtension(true, 0, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
        new x509.CertificatePolicyExtension([OID_ANY_POLICY]),
        await x509.SubjectKeyIdentifierExtension.create(caKeys.publicKey),
      ],
    })
    writeDataFile('trust-list/access-ca-key.pem', toPem('PRIVATE KEY', await webcrypto.subtle.exportKey('pkcs8', caKeys.privateKey)))
    writeDataFile('trust-list/access-ca-cert.pem', caCert.toString('pem'))
  }

  const issued: IssuedCertificate[] = existsSync(statePath) ? JSON.parse(readFileSync(statePath, 'utf-8')) : []
  const persist = () => writeDataFile('trust-list/access-ca-issued.json', issued)

  return {
    caCert,
    crlUri,
    caIssuersUri,
    issued,

    /** Issues a WRPAC (ETSI TS 119 411-8, NCP-l-eudiwrp). */
    async issue(req: WrpacRequest): Promise<x509.X509Certificate> {
      const notBefore = new Date(Date.now() - 60_000)
      const notAfter = new Date(Date.now() + 365 * 24 * 3600 * 1000)
      // positive serial number (RFC 5280): leading byte < 0x80
      const serial = `${(randomBytes(1)[0] & 0x7f).toString(16).padStart(2, '0')}${randomBytes(15).toString('hex')}`
      // structured name: values may contain commas (e.g. "Co., Ltd.")
      const subjectName = new x509.Name([
        { C: [req.country] },
        { O: [req.organizationName] },
        { [OID_ORGANIZATION_IDENTIFIER]: [req.organizationIdentifier] },
        { CN: [req.commonName] },
      ])
      const subject = subjectName.toString()
      const cert = await x509.X509CertificateGenerator.create({
        serialNumber: serial,
        subject: subjectName,
        issuer: caCert.subject,
        notBefore,
        notAfter,
        signingAlgorithm: EC,
        publicKey: req.publicKey,
        signingKey: caKeys.privateKey,
        extensions: [
          new x509.BasicConstraintsExtension(false, undefined, false),
          new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
          new x509.CertificatePolicyExtension([ETSI119411_8.NCP_L_EUDIWRP]),
          new x509.SubjectAlternativeNameExtension([
            { type: 'dns', value: req.dnsName },
            { type: 'url', value: req.contactUri },
          ]),
          await x509.AuthorityKeyIdentifierExtension.create(caCert),
          await x509.SubjectKeyIdentifierExtension.create(req.publicKey),
          new x509.CRLDistributionPointsExtension([crlUri]),
          new x509.AuthorityInfoAccessExtension({ caIssuers: new x509.GeneralName('url', caIssuersUri) }),
        ],
      })
      issued.push({
        serial,
        clientId: req.clientId,
        subject,
        notBefore: notBefore.toISOString(),
        notAfter: notAfter.toISOString(),
      })
      persist()
      return cert
    },

    /** Revokes every valid access certificate of a Relying Party (registration suspended / cancelled). */
    revokeAllOf(clientId: string, reason: x509.X509CrlReason) {
      for (const c of issued) {
        if (c.clientId === clientId && !c.revoked) c.revoked = { at: new Date().toISOString(), reason }
      }
      persist()
    },

    /** Removes certificateHold entries again (suspension lifted). */
    releaseHold(clientId: string) {
      for (const c of issued) {
        if (c.clientId === clientId && c.revoked?.reason === x509.X509CrlReason.certificateHold) delete c.revoked
      }
      persist()
    },

    /** Current CRL (DER), valid for one hour. */
    async crl(): Promise<ArrayBuffer> {
      const crl = await x509.X509CrlGenerator.create({
        issuer: caCert.subject,
        thisUpdate: new Date(Date.now() - 60_000),
        nextUpdate: new Date(Date.now() + 60 * 60 * 1000),
        signingAlgorithm: EC,
        signingKey: caKeys.privateKey,
        extensions: [await x509.AuthorityKeyIdentifierExtension.create(caCert)],
        entries: issued
          .filter((c) => c.revoked)
          .map((c) => ({
            serialNumber: c.serial,
            revocationDate: new Date(c.revoked?.at as string),
            reason: c.revoked?.reason,
          })),
      })
      return crl.rawData
    },
  }
}
