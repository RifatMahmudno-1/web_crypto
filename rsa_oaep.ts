/**
 * converts a base64 encoded key to PEM format
 * @param key actual key string in base64 format
 * @param keyType rsa key type, either 'public' or 'private'
 * @returns PEM formatted key string
 */
function convertToPemFormat(key: string, keyType: 'public' | 'private') {
	const pemHeader = keyType === 'public' ? 'PUBLIC KEY' : 'PRIVATE KEY'
	const pemFormatted = [`-----BEGIN ${pemHeader}-----`, key.match(/.{1,64}/g)?.join('\n') || key, `-----END ${pemHeader}-----`].join('\n')

	return pemFormatted
}

/**
 * converts a PEM formatted key to base64 format
 * @param pemKey PEM formatted key string
 * @returns base64 encoded key string
 */
function convertFromPemFormat(pemKey: string) {
	const pemContents = pemKey
		.replace(/-----BEGIN [\w\s]+-----/, '')
		.replace(/-----END [\w\s]+-----/, '')
		.replace(/\s/g, '')

	return pemContents
}

/**
 * Returns a generated RSA key pair of 2048 bits for RSA-OAEP with SHA-256
 * @param keyFormat format of the keys, either 'pem' or 'base64' (default: 'pem')
 * @returns object containing publicKey and privateKey
 */
async function generateRSAKeyPair(keyFormat: 'pem' | 'base64' = 'pem') {
	const keyPair = await globalThis.crypto.subtle.generateKey(
		{
			name: 'RSA-OAEP',
			modulusLength: 2048,
			publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
			hash: 'SHA-256'
		},
		true,
		['encrypt', 'decrypt']
	)

	const exportedPublicKey = await globalThis.crypto.subtle.exportKey('spki', keyPair.publicKey)
	const base64PublicKey = btoa(String.fromCharCode(...new Uint8Array(exportedPublicKey)))

	const exportedPrivateKey = await globalThis.crypto.subtle.exportKey('pkcs8', keyPair.privateKey)
	const base64PrivateKey = btoa(String.fromCharCode(...new Uint8Array(exportedPrivateKey)))

	return {
		publicKey: keyFormat === 'base64' ? base64PublicKey : convertToPemFormat(base64PublicKey, 'public'),
		privateKey: keyFormat === 'base64' ? base64PrivateKey : convertToPemFormat(base64PrivateKey, 'private')
	}
}

/**
 *
 * @param pemPublicKey public key in PEM format or base64 format
 * @param keyFormat format of the public key, either 'pem' or 'base64' (default: 'pem')
 * @param data data as string to be encrypted. Maximum length is 190 bytes.
 * @returns encrypted data in base64 format
 */
async function encrypt(pemPublicKey: string, data: string, keyFormat: 'pem' | 'base64' = 'pem') {
	// serialize public key
	const base64key = keyFormat === 'base64' ? pemPublicKey : convertFromPemFormat(pemPublicKey)
	const publicKeyBytes = new Uint8Array(
		atob(base64key)
			.split('')
			.map(c => c.charCodeAt(0))
	)
	const publicKey = await globalThis.crypto.subtle.importKey(
		'spki',
		publicKeyBytes,
		{
			name: 'RSA-OAEP',
			hash: 'SHA-256'
		},
		true,
		['encrypt']
	)

	// convert data to Uint8Array
	const dataBuffer = new TextEncoder().encode(data)

	// encrypt
	const encrypted = await globalThis.crypto.subtle.encrypt(
		{
			name: 'RSA-OAEP'
		},
		publicKey,
		dataBuffer
	)

	return btoa(String.fromCharCode(...new Uint8Array(encrypted)))
}

/**
 * @param pemPrivateKey private key in PEM format or base64 format
 * @param keyFormat format of the private key, either 'pem' or 'base64' (default: 'pem')
 * @param base64EncryptedData encrypted data in base64 format
 * @returns decrypted data as string
 */
async function decrypt(pemPrivateKey: string, base64EncryptedData: string, keyFormat: 'pem' | 'base64' = 'pem') {
	// serialize private key
	const base64key = keyFormat === 'base64' ? pemPrivateKey : convertFromPemFormat(pemPrivateKey)
	const privateKeyBytes = new Uint8Array(
		atob(base64key)
			.split('')
			.map(c => c.charCodeAt(0))
	)
	const privateKey = await globalThis.crypto.subtle.importKey(
		'pkcs8',
		privateKeyBytes,
		{
			name: 'RSA-OAEP',
			hash: 'SHA-256'
		},
		true,
		['decrypt']
	)

	// convert base64 to Uint8Array
	const encryptedData = new Uint8Array(
		atob(base64EncryptedData)
			.split('')
			.map(c => c.charCodeAt(0))
	)

	// decrypt
	const decrypted = await globalThis.crypto.subtle.decrypt(
		{
			name: 'RSA-OAEP'
		},
		privateKey,
		encryptedData
	)

	return new TextDecoder().decode(new Uint8Array(decrypted))
}

export { generateRSAKeyPair, encrypt, decrypt, convertFromPemFormat, convertToPemFormat }
