import hdkey from 'hdkey';
import bip39 from 'bip39';
import { getPublic } from './keytool';

const ICP_PATH = `m/44'/223'/0'`;

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
): Promise<{ prv: string; pub: string; pubCompressed: string; xpub: string }> {
	if (!isValidMnemonic(mnemonic)) {
		throw new Error('Mnemonic invalid or undefined');
	}

	const node = hdkey.fromMasterSeed(await bip39.mnemonicToSeed(mnemonic));
	const masterPrv = node.derive(`${ICP_PATH}/0/${index}`);
	const masterPrvRaw = node.derive(`${ICP_PATH}`);
	const prv = masterPrv.privateKey.toString('hex');
	const pub = getPublic(prv, false);
	const pubCompressed = getPublic(prv, true);
	masterPrv.wipePrivateData();
	masterPrvRaw.wipePrivateData();
	const xpub = masterPrvRaw.publicExtendedKey;
	return { prv, pub, pubCompressed, xpub };
}
