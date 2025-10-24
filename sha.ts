async function sha(data: BufferSource, algorithm: 'SHA-256' | 'SHA-384' | 'SHA-512' | 'SHA-1') {
	if (!['SHA-256', 'SHA-384', 'SHA-512', 'SHA-1'].includes(algorithm)) throw new Error('[algorithm] must be SHA-256 or SHA-384 or SHA-512 or SHA-1')

	const byteBuffer = await globalThis.crypto.subtle.digest(algorithm, data)
	const byteArray = new Uint8Array(byteBuffer)
	let hex = ''
	for (let i = 0; i < byteArray.length; i++) {
		hex += byteArray[i]!.toString(16).padStart(2, '0')
	}
	return hex
}

export default sha
