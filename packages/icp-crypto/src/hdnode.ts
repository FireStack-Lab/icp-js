import hdkey from 'hdkey';
import bip39 from 'bip39';
import { getPublic } from './keytool';

const ICP_PATH = `m/44'/223'/0'/0/`;

export function isValidMnemonic(phrase: string): boolean {
	if (phrase.trim().split(/\s+/g).length < 12) {
		return false;
	}

	return bip39.validateMnemonic(phrase);
}

export function generateMnemonic(): string {
	return bip39.generateMnemonic();
}

export async function getKeyPair(
	mnemonic: string,
	index: number = 0
): Promise<{ prv: string; pub: string }> {
	if (!isValidMnemonic(mnemonic)) {
		throw new Error('Mnemonic invalid or undefined');
	}

	const prv = hdkey
		.fromMasterSeed(await bip39.mnemonicToSeed(mnemonic))
		.derive(`${ICP_PATH}${index}`)
		.privateKey.toString('hex');
	const pub = getPublic(prv, false);

	return { prv, pub };
}
