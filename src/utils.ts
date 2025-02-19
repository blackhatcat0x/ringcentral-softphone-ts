// Modified utils.ts for forked repository
import crypto from "crypto";
import { SoftPhoneOptions } from "./types";

// Updated generateResponse with proper digest auth
const generateResponse = (
  sipInfo: SoftPhoneOptions,
  method: string,
  uri: string,
  nonce: string,
  nc: string,
  cnonce: string,
  qop: string
) => {
  // Generate HA1 = MD5(username:realm:password)
  const ha1 = crypto.createHash('md5')
    .update(`${sipInfo.authorizationId}:${sipInfo.domain}:${sipInfo.password}`)
    .digest('hex');

  // Generate HA2 = MD5(method:digestURI)
  const ha2 = crypto.createHash('md5')
    .update(`${method}:${uri}`)
    .digest('hex');

  // Generate final response
  // MD5(HA1:nonce:nc:cnonce:qop:HA2)
  const response = crypto.createHash('md5')
    .update(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`)
    .digest('hex');

  return response;
};

export const generateAuthorization = (
  sipInfo: SoftPhoneOptions,
  nonce: string,
  method: "REGISTER" | "INVITE",
) => {
  const nc = '00000001';
  const cnonce = crypto.randomBytes(8).toString('hex');
  const qop = 'auth';
  const uri = `sip:${sipInfo.domain}`;

  const response = generateResponse(
    sipInfo,
    method,
    uri,
    nonce,
    nc,
    cnonce,
    qop
  );

  const authParams = {
    username: sipInfo.authorizationId,
    realm: sipInfo.domain,
    nonce: nonce,
    uri: uri,
    algorithm: 'MD5',
    qop: qop,
    nc: nc,
    cnonce: cnonce,
    response: response,
    opaque: ''
  };

  // Format into Digest auth header
  return Object.entries(authParams)
    .map(([key, value]) => `${key}="${value}"`)
    .join(', ');
};

// Helper functions
export const uuid = () => crypto.randomUUID();
export const branch = () => "z9hG4bK-" + uuid();
export const randomInt = () => Math.floor(Math.random() * (65535 - 1024 + 1)) + 1024;
export const withoutTag = (s: string) => s.replace(/;tag=.*$/, "");
export const extractAddress = (s: string) => s.match(/<(sip:.+?)>/)?.[1];

// Generate encryption keys
const keyAndSalt = crypto.randomBytes(30);
export const localKey = keyAndSalt.toString("base64").replace(/=+$/, "");
