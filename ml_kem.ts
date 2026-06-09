const webcrypto = globalThis.crypto

/**
 * Generates an ML-KEM public and private key pair for the specified algorithm.
 * @param algorithm the ML-KEM algorithm to use, either 'ML-KEM-1024' or 'ML-KEM-768'
 * @returns a CryptoKeyPair containing the generated public and private keys
 */
export async function generateMLKEMKeyPair(algorithm: 'ML-KEM-1024' | 'ML-KEM-768'): Promise<CryptoKeyPair> {
	const keyPair = await webcrypto.subtle.generateKey(
		{ name: algorithm },
		true,
		// @ts-ignore - not yet recognized by TypeScript
		['encapsulateBits', 'decapsulateBits']
	)
	return keyPair
}

/**
 * Exports an ML-KEM public or private key to a Base64 string.
 * @param key the CryptoKey to export
 * @returns the Base64 encoded string representation of the key
 */
export async function exportKeyToString(key: CryptoKeyPair['publicKey'] | CryptoKeyPair['privateKey']) {
	const keyBuffer = await webcrypto.subtle.exportKey(key.type === 'public' ? 'spki' : 'pkcs8', key)
	return arrayBufferToBase64(keyBuffer)
}

/**
 * Imports an ML-KEM public or private key from a Base64 string.
 * @param keyString the Base64 encoded string representation of the key
 * @param algorithm the ML-KEM algorithm to use, either 'ML-KEM-1024' or 'ML-KEM-768'
 * @param type the type of key to import, either 'publicKey' or 'privateKey'
 * @returns a CryptoKey representing the imported key
 */
export async function importKeyFromString(keyString: string, algorithm: 'ML-KEM-1024' | 'ML-KEM-768', type: 'publicKey' | 'privateKey') {
	const keyBuffer = base64ToArrayBuffer(keyString)

	const key = await webcrypto.subtle.importKey(
		type === 'publicKey' ? 'spki' : 'pkcs8',
		keyBuffer,
		{ name: algorithm },
		true,
		// @ts-ignore - not yet recognized by TypeScript
		type === 'publicKey' ? ['encapsulateBits'] : ['decapsulateBits']
	)

	return key
}

/**
 * Encapsulates a shared secret using the recipient's public key and returns the ciphertext and shared key.
 * @param publicKey the recipient's public key
 * @returns an object containing the ciphertext and shared key as ArrayBuffers
 */
export async function encapsulateSecret(publicKey: CryptoKeyPair['publicKey']): Promise<{ ciphertext: ArrayBuffer; sharedKey: ArrayBuffer }> {
	// @ts-ignore - not yet recognized by TypeScript
	const { ciphertext, sharedKey } = await webcrypto.subtle.encapsulateBits({ name: publicKey.algorithm.name }, publicKey)
	return { ciphertext, sharedKey }
}

/**
 * Decapsulates the shared secret from the given ciphertext using the recipient's private key.
 * @param privateKey the recipient's private key
 * @param ciphertext the ciphertext to decapsulate
 * @returns the shared secret as an ArrayBuffer
 */
export async function decapsulateSecret(privateKey: CryptoKeyPair['privateKey'], ciphertext: ArrayBuffer): Promise<ArrayBuffer> {
	// @ts-ignore - not yet recognized by TypeScript
	const sharedSecret = await webcrypto.subtle.decapsulateBits({ name: privateKey.algorithm.name }, privateKey, ciphertext)
	return sharedSecret
}

/**
 * Utility function to convert an ArrayBuffer to a Base64 string.
 * @param buffer the ArrayBuffer to convert
 * @returns the Base64 encoded string
 */
export function arrayBufferToBase64(buffer: ArrayBuffer) {
	const bytes = new Uint8Array(buffer)
	const len = bytes.byteLength
	let binaryString = ''
	for (let i = 0; i < len; i++) {
		binaryString += String.fromCharCode(bytes[i]!)
	}
	return btoa(binaryString)
}

/**
 * Utility function to convert a Base64 string to an ArrayBuffer.
 * @param base64 the Base64 string to convert
 * @returns the resulting ArrayBuffer
 */
export function base64ToArrayBuffer(base64: string) {
	const binaryString = atob(base64)
	const len = binaryString.length
	const bytes = new Uint8Array(len)
	for (let i = 0; i < len; i++) {
		bytes[i] = binaryString.charCodeAt(i)
	}
	return bytes.buffer
}

/**
 * converts a base64 encoded key to PEM format
 * @param key actual key string in base64 format
 * @param keyType 'public' or 'private'
 * @returns PEM formatted key string
 */
export function convertToPemFormat(key: string, keyType: 'public' | 'private') {
	const pemHeader = keyType === 'public' ? 'PUBLIC KEY' : 'PRIVATE KEY'
	const pemFormatted = [`-----BEGIN ${pemHeader}-----`, key.match(/.{1,64}/g)?.join('\n') || key, `-----END ${pemHeader}-----`].join('\n')

	return pemFormatted
}

/**
 * converts a PEM formatted key to base64 format
 * @param pemKey PEM formatted key string
 * @returns base64 encoded key string
 */
export function convertFromPemFormat(pemKey: string) {
	const pemContents = pemKey
		.replace(/-----BEGIN [\w\s]+-----/, '')
		.replace(/-----END [\w\s]+-----/, '')
		.replace(/\s/g, '')

	return pemContents
}
