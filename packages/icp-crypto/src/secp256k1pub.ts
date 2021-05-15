import { agent } from '@icp-js/utils';

class Secp256k1PublicKey implements agent.PublicKey {
	private readonly rawKey: agent.BinaryBlob;
	private readonly derKey: agent.DerEncodedBlob;
	private static RAW_KEY_LENGTH = 65;
	private static DER_PREFIX = Uint8Array.from([
		0x30,
		0x56,
		0x30,
		0x10,
		0x06,
		0x07,
		0x2a,
		0x86,
		0x48,
		0xce,
		0x3d,
		0x02,
		0x01,
		0x06,
		0x05,
		0x2b,
		0x81,
		0x04,
		0x00,
		0x0a,
		0x03,
		0x42,
		0x00, // no padding
	]);
	constructor(key: agent.BinaryBlob) {
		this.rawKey = key;
		this.derKey = Secp256k1PublicKey.derEncode(key);
	}
	static fromRaw(rawKey: agent.BinaryBlob) {
		return new Secp256k1PublicKey(rawKey);
	}
	static fromDer(derKey: agent.BinaryBlob) {
		return new Secp256k1PublicKey(this.derDecode(derKey));
	}
	private static derEncode(publicKey: agent.BinaryBlob) {
		if (publicKey.byteLength !== Secp256k1PublicKey.RAW_KEY_LENGTH) {
			const bl = publicKey.byteLength;
			throw new TypeError(
				`secp256k1 public key must be ${Secp256k1PublicKey.RAW_KEY_LENGTH} bytes long (is ${bl})`
			);
		}
		const derPublicKey = Uint8Array.from([
			...Secp256k1PublicKey.DER_PREFIX,
			...new Uint8Array(publicKey),
		]);
		return agent.derBlobFromBlob(agent.blobFromUint8Array(derPublicKey));
	}
	private static derDecode(key: agent.BinaryBlob) {
		const expectedLength = Secp256k1PublicKey.DER_PREFIX.length + Secp256k1PublicKey.RAW_KEY_LENGTH;
		if (key.byteLength !== expectedLength) {
			const bl = key.byteLength;
			throw new TypeError(
				`secp256k1 DER-encoded public key must be ${expectedLength} bytes long (is ${bl})`
			);
		}
		const rawKey = agent.blobFromUint8Array(key.subarray(Secp256k1PublicKey.DER_PREFIX.length));
		if (!this.derEncode(rawKey).equals(key)) {
			throw new TypeError(
				'secp256k1 DER-encoded public key is invalid. A valid secp256k1 DER-encoded public key ' +
					`must have the following prefix: ${Secp256k1PublicKey.DER_PREFIX}`
			);
		}
		return rawKey;
	}
	toDer() {
		return this.derKey;
	}
	toRaw() {
		return this.rawKey;
	}
}

export { Secp256k1PublicKey };
