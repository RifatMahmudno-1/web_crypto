/**
 * Derives a 256-bit key from the provided key using SHA-256.
 */
async function deriveKey(key: string, algorithm: 'AES-GCM' | 'AES-CBC' | 'AES-CTR') {
	const encodedKey = new TextEncoder().encode(key)
	const hash = await globalThis.crypto.subtle.digest('SHA-256', encodedKey)
	return globalThis.crypto.subtle.importKey('raw', hash, { name: algorithm }, false, ['encrypt', 'decrypt'])
}

/**
 * Derives a 256-bit HMAC key from the provided key using SHA-256.
 */
async function deriveHMACKey(key: string) {
	const encodedKey = new TextEncoder().encode(key)
	const hash = await globalThis.crypto.subtle.digest('SHA-256', encodedKey)
	return globalThis.crypto.subtle.importKey('raw', hash, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify'])
}

function toBase64Url(buffer: Uint8Array) {
	return btoa(String.fromCodePoint(...buffer))
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '')
}

function fromBase64Url(base64url: string) {
	return base64url.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (base64url.length % 4)) % 4)
}

/**
 * Encrypts the text using specified algorithm using Web Crypto API.
 */
async function encrypt(
	text: string,
	key: string,
	algorithm: 'AES-GCM' | 'AES-CBC' | 'AES-CTR',
	{
		textEncoding,
		withHMAC
	}: {
		textEncoding?: 'base64' | 'base64url'
		withHMAC?: boolean
	}
) {
	if (!text || typeof text !== 'string') throw new Error('[text] must be a non-empty string.')
	if (!key || typeof key !== 'string') throw new Error('[key] must be a non-empty string.')
	if (!algorithm || typeof algorithm !== 'string' || !['AES-GCM', 'AES-CBC', 'AES-CTR'].includes(algorithm)) throw new Error('[algorithm] must be AES-GCM or AES-CBC or AES-CTR')
	if (textEncoding === undefined) textEncoding = 'base64'
	else if (!['base64', 'base64url'].includes(textEncoding)) throw new Error('[textEncoding] must be a base64 or base64url or undefined.')
	if (withHMAC === undefined) withHMAC = false
	else if (typeof withHMAC !== 'boolean') throw new Error('[withHMAC] must be a boolean or undefined.')

	const encryptionKey = await deriveKey(key, algorithm)
	const iv = globalThis.crypto.getRandomValues(new Uint8Array(16))
	const encrypted = await globalThis.crypto.subtle.encrypt(algorithm === 'AES-CTR' ? { name: algorithm, counter: iv, length: 128 } : { name: algorithm, iv }, encryptionKey, new TextEncoder().encode(text))

	const encryptedArray = new Uint8Array(encrypted)
	let buffer = new Uint8Array(encryptedArray.length + iv.length)
	buffer.set(iv, 0)
	buffer.set(encryptedArray, iv.length)

	if (withHMAC) {
		const hmacKey = await deriveHMACKey(key)
		const hmac = await globalThis.crypto.subtle.sign('HMAC', hmacKey, buffer)
		const bufferWithHmac = new Uint8Array(buffer.length + hmac.byteLength)
		bufferWithHmac.set(buffer, 0)
		bufferWithHmac.set(new Uint8Array(hmac), buffer.length)
		buffer = bufferWithHmac
	}

	return textEncoding === 'base64' ? btoa(String.fromCodePoint(...buffer)) : toBase64Url(buffer)
}

/**
 * Decrypts the text using specified algorithm using Web Crypto API.
 */
async function decrypt(
	encryptedText: string,
	key: string,
	algorithm: 'AES-GCM' | 'AES-CBC' | 'AES-CTR',
	{
		encryptedTextEncoding,
		withHMAC
	}: {
		encryptedTextEncoding?: 'base64' | 'base64url'
		withHMAC?: boolean
	}
) {
	if (!encryptedText || typeof encryptedText !== 'string') throw new Error('[encryptedText] must be a non-empty string.')
	if (!key || typeof key !== 'string') throw new Error('[key] must be a non-empty string.')
	if (!algorithm || !['AES-GCM', 'AES-CBC', 'AES-CTR'].includes(algorithm)) throw new Error('[algorithm] must be AES-GCM or AES-CBC or AES-CTR')
	if (encryptedTextEncoding === undefined) encryptedTextEncoding = 'base64'
	else if (!['base64', 'base64url'].includes(encryptedTextEncoding)) throw new Error('[encryptedTextEncoding] must be a base64 or base64url or undefined.')
	if (withHMAC === undefined) withHMAC = false
	else if (typeof withHMAC !== 'boolean') throw new Error('[withHMAC] must be a boolean or undefined.')

	const encryptionKey = await deriveKey(key, algorithm)
	let buffer = new Uint8Array(
		atob(encryptedTextEncoding === 'base64' ? encryptedText : fromBase64Url(encryptedText))
			.split('')
			.map(char => char.charCodeAt(0))
	)

	if (withHMAC) {
		const hmacKey = await deriveHMACKey(key)
		const hmac = buffer.slice(buffer.length - 32)
		buffer = buffer.slice(0, buffer.length - 32)
		const validHMAC = await globalThis.crypto.subtle.verify('HMAC', hmacKey, hmac, buffer)
		if (!validHMAC) throw new Error('HMAC verification failed. The message may have been tampered with.')
	}

	const iv = buffer.slice(0, 16)
	const encryptedData = buffer.slice(16)

	const decrypted = await globalThis.crypto.subtle.decrypt(algorithm === 'AES-CTR' ? { name: algorithm, counter: iv, length: 128 } : { name: algorithm, iv }, encryptionKey, encryptedData)
	return new TextDecoder().decode(decrypted)
}

export default { encrypt, decrypt }
export { encrypt }
export { decrypt }
