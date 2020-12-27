import secp from 'secp256k1';
import ethUtil from 'ethereumjs-util';
import { sha3_256 } from 'js-sha3';

/**
 * Get the address from signature and  hash  of the  payload
 * @param signature The input data (String)
 * @param payload   The hash of the data which was signed with ICONex wallet
 */
const getAddressFromSignature = function(signature, payload){
    const signatureArray = Buffer.from(signature, 'base64');
	const signatureBuffer = signatureArray.subarray(0, 64);
	const recoveryBuffer = signatureArray.subarray(64);

	//Genrate the puablic key from signature, recovery_key and payload
	const publicKey = secp.ecdsaRecover(signatureBuffer,
		parseInt(recoveryBuffer.toString('hex')),
		new Uint8Array(Buffer.from(payload, 'hex')),
		false);
	const publicKeyBuffer = ethUtil.toBuffer(publicKey.slice(1));

	//Decode the address from public key hash by taking last 40 bytes
	//Adding hx as prefix for idenitifying the EOA in ICON
	const decodedAddress = 'hx' + sha3_256(publicKeyBuffer).slice(-40);

	return decodedAddress;
}

/**
 * Checks if the signature is  signed by the particular address
 * @param signature The input data (String)
 * @param address   The user address with which the signature was signed (String)
 * @param payload   The hash of the data which was signed with ICONex wallet
 */
const validateSignature = function(signature, address, payload){
	const decodedAddress = getAddressFromSignature(signature, payload)

    return address === decodedAddress;
}

module.exports = {
    getAddressFromSignature,
    validateSignature
}