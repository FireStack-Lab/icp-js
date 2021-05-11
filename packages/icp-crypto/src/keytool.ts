import elliptic from 'elliptic';
import { isPrivateKey, strip0x } from '@icp-js/utils';

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
