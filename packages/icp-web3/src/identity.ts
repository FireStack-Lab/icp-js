import {
	BinaryBlob,
	// blobFromHex,
	blobFromUint8Array,
	// derBlobFromBlob,
	DerEncodedBlob,
	PublicKey,
	// SignIdentity,
} from '@dfinity/agent';

import {
	// Secp256k1PublicKey,
	recoverPublicKeyFromHash,
} from '@icp-js/crypto';

import Web3 from 'web3';

// import borc from 'borc';

import { WebAuthnIdentity } from '@dfinity/identity';

export type CredentialId = BinaryBlob;
export type CredentialData = {
	pubkey: DerEncodedBlob;
	credentialId: CredentialId;
};

interface Web3Obj {
	web3: any;
	accounts: string[];
	address: string;
	networkId: number;
	chainId: number;
}

export class Web3Auth extends WebAuthnIdentity {
	// constructor() {
	// 	super();
	// }

	public web3: any;
	public accounts: string[] = [];
	public address?: string = undefined;
	public chainId?: number = undefined;
	private _web3PublicKey?: PublicKey = undefined;

	constructor(web3: Web3Obj, pubKey: BinaryBlob) {
		// rawId: BinaryBlob, cose: BinaryBlob
		super(blobFromUint8Array(Buffer.from(web3.address)), pubKey);
	}

	static async initWeb3(provider: any) {
		try {
			const web3: any = new Web3(provider);

			web3.eth.extend({
				methods: [
					{
						name: 'chainId',
						call: 'eth_chainId',
						outputFormatter: web3.utils.hexToNumber,
					},
				],
			});

			const accounts: string[] = await web3.eth.getAccounts();

			const address: string = accounts[0];

			const networkId: number = await web3.eth.net.getId();

			const chainId: number = await web3.eth.chainId();

			return {
				web3,
				accounts,
				address,
				networkId,
				chainId,
			};
		} catch (e) {
			throw new Error(`Web3 init failed: ${e.message}`);
		}
	}

	static async create(provider?: any) {
		const web3Obj = await Web3Auth.initWeb3(provider);
		if (web3Obj.address == undefined) {
			throw new Error('Web3Identity create failed, please retry');
		}
		// TODO: should check if identy is existed

		try {
			const extractedPubkey = blobFromUint8Array(
				Buffer.from(Web3Auth.extractPublicKeyFromWeb3(web3Obj))
			);
			return new Web3Auth(web3Obj as Web3Obj, extractedPubkey);
		} catch (e) {
			throw new Error('cannot extract public key from Web3');
		}
		//
	}

	static async extractPublicKeyFromWeb3(web3Obj: Web3Obj): Promise<string> {
		const typeToSign = JSON.stringify({
			domain: {
				// Defining the chain aka Rinkeby testnet or Ethereum Main Net
				chainId: web3Obj.chainId,
				// Give a user friendly name to the specific contract you are signing for.
				name: 'Web3',
				// // If name isn't enough add verifying contract to make sure you are establishing contracts with the proper entity
				// verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
				// Just let's you know the latest version. Definitely make sure the field name is correct.
				version: '1',
			},

			// Defining the message signing data content.
			message: {
				/*
	 - Anything you want. Just a JSON Blob that encodes the data you want to send
	 - No required fields
	 - This is DApp Specific
	 - Be as explicit as possible when building out the message schema.
	*/
				contents: 'Hello, Bob!',
				attachedMoneyInEth: 4.2,
				from: {
					name: 'Cow',
					wallets: [
						'0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
						'0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF',
					],
				},
				to: [
					{
						name: 'Bob',
						wallets: [
							'0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
							'0xB0BdaBea57B0BDABeA57b0bdABEA57b0BDabEa57',
							'0xB0B0b0b0b0b0B000000000000000000000000000',
						],
					},
				],
			},
			// Refers to the keys of the *types* object below.
			primaryType: 'Mail',
			types: {
				// TODO: Clarify if EIP712Domain refers to the domain the contract is hosted on
				EIP712Domain: [
					{ name: 'name', type: 'string' },
					{ name: 'version', type: 'string' },
					{ name: 'chainId', type: 'uint256' },
					// { name: 'verifyingContract', type: 'address' },
				],
				// Not an EIP712Domain definition
				Group: [
					{ name: 'name', type: 'string' },
					{ name: 'members', type: 'Person[]' },
				],
				// Refer to PrimaryType
				Mail: [
					{ name: 'from', type: 'Person' },
					{ name: 'to', type: 'Person[]' },
					{ name: 'contents', type: 'string' },
				],
				// Not an EIP712Domain definition
				Person: [
					{ name: 'name', type: 'string' },
					{ name: 'wallets', type: 'address[]' },
				],
			},
		});
		const message = {
			method: 'eth_signTypedData_v4',
			params: [web3Obj.address, typeToSign],
		};
		const hash = await web3Obj.web3.currentProvider.request(message);
		return recoverPublicKeyFromHash(<string>hash, typeToSign);
	}

	public getPublicKey(): PublicKey {
		if (this.address == undefined) {
			throw new Error('cannot use getPublicKey() before a successful sign()');
		} else {
			return this._web3PublicKey!;
		}
	}

	public async sign(blob: BinaryBlob): Promise<BinaryBlob> {
		const result = blob;
		// psudo sign
		return result;
	}
}
