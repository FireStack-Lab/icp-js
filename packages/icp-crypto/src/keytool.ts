import elliptic from 'elliptic';
import { agent, isPrivateKey, strip0x, utf8ToBytes } from '@icp-js/utils';
import * as sigUtil from 'eth-sig-util';
import { sha224 as jsSha224 } from 'js-sha256';
import { keccak256 } from './keccak256';
import { Secp256k1PublicKey } from './secp256k1pub';
import { getCrc32 } from './crc';
// import { encode } from './base32';

const secp256k1 = elliptic.ec('secp256k1');

export const getPublic = (privateKey: string, compress?: boolean): string => {
	if (!isPrivateKey(privateKey) || !validatePrivateKey(privateKey)) {
		throw new Error(`${privateKey} is not PrivateKey`);
	}
	const ecKey = secp256k1.keyFromPrivate(strip0x(privateKey), 'hex');

	return ecKey.getPublic(compress || false, 'hex');
};

export const validatePrivateKey = (privateKey: string): boolean => {
	const ecKey = secp256k1.keyFromPrivate(strip0x(privateKey), 'hex');
	const { result } = ecKey.validate();
	return result;
};

/**
 * @function getAddressFromPublicKey
 * @param  {string} publicKey - public key string
 * @return {string} address with `length = 40`
 */
export const getAddressFromPublicKey = (publicKey: string, with0x: boolean = false): string => {
	const publicHash = getUncompressPublicKey(publicKey);
	const address = keccak256('0x' + publicHash.slice(2)).slice(-40);
	return with0x ? '0x' + address : address;
};

/**
 * @function getUncompressPublicKey
 * @param  {string} publicKey- public key
 * @return {string} Uncompress public key
 */
export const getUncompressPublicKey = (publicKey: string): string => {
	const ecKey = secp256k1.keyFromPublic(
		publicKey.startsWith('0x') ? publicKey.slice(2) : publicKey,
		'hex'
	);
	return ecKey.getPublic(false, 'hex');
};

/**
 * @function getSecp256k1FromPublicKey
 * @param  {string} publicKey: uncompressed public key
 * @return {string} : secp256k1 public key
 */
export const getSecp256k1FromPublicKey = (publicKey: string): string => {
	return Secp256k1PublicKey.fromRaw(agent.blobFromHex(publicKey)).toDer().toString('hex');
};

/**
 * @function getPrincipalFromPublicKey
 * @param  {string} publicKey: uncompressed public key
 * @return {string} {principal text}
 */
export const getPrincipalFromPublicKey = (publicKey: string): string => {
	const secp256k1Pub = Secp256k1PublicKey.fromRaw(agent.blobFromHex(publicKey)).toDer();
	const auth = agent.Principal.selfAuthenticating(secp256k1Pub);
	return auth.toText();
};

/**
 * @function getAccountIdFromPublicKey
 * @param  {string} publicKey: uncompressed public key
 * @return {string} accountId
 */
export const getAccountIdFromPublicKey = (publicKey: string): string => {
	const der = Secp256k1PublicKey.fromRaw(agent.blobFromHex(publicKey)).toDer();
	const hash = jsSha224.create();
	hash.update(Buffer.from(utf8ToBytes('\x0Aaccount-id')));
	hash.update(agent.Principal.selfAuthenticating(der).toBlob());
	hash.update(Buffer.from(new Uint8Array(32)));
	const data = hash.digest();
	const checksumArrayBuf = new ArrayBuffer(4);
	const view = new DataView(checksumArrayBuf);
	view.setUint32(0, getCrc32(Buffer.from(data)), false);
	const checksum = Uint8Array.from(Buffer.from(checksumArrayBuf));
	const bytes = Uint8Array.from(data);
	const array = new Uint8Array([...checksum, ...bytes]);

	return Buffer.from(array).toString('hex');
};

export const recoverPublicKeyFromHash = (hash: string, originMessage: string) => {
	const msgParams = { data: originMessage, sig: hash };
	return sigUtil
		.extractPublicKey(
			// msgParams as sigUtil.SignedMsgParams<string>
			msgParams
		)
		.replace('0x', '04');
};
