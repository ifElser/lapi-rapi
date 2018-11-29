const isClient = typeof window !== 'undefined'

const TextAPI = isClient ? {
	encode: text => (new TextEncoder()).encode(text),
	decode: data => (new TextDecoder()).decode(Uint8Array.from(data))
} : {
	encode: text => Buffer.from(text),
	decode: data => Buffer.from(data).toString('utf8')
}

module.exports = class BitChaos {

	constructor (secret) {

		secret = Uint8Array.from(secret).filter(byte => !!byte)

		function origin (chunk, length) {
			let result = chunk
			length = length & 3
	    const logic = {

				add: (key) => {
					let ring = 255, len = length
					while(--len) { ring = (ring << 8) | ring };
					result = (result + key) & ring
					return logic
				},

				sub: (key) => {
					let ring = 255, len = length
					while(--len) { ring = (ring << 8) | ring };
					result = (result >= key ? result - key : ring + 1 + result - key)
					return logic
				},

				xor: (key) => {
					result = result ^ key
					return logic
				},

				done: () => result

			}
			return logic
		}

		this.encrypt = (message, mode = 'array') => {
			const fns = ['add', 'sub', 'xor']
			if(typeof message === 'string') message = TextAPI.encode(message); else
			if(message instanceof ArrayBuffer) message = new Uint8Array(message); else
    	if(!(message instanceof Uint8Array)) message = Uint8Array.from(message)
			const data = Uint8Array.from(message)
			const slen = secret.length
			const dlen = data.length
			let encrypted = []
			const mask = 192
			let sptr = 0
			let dptr = 0
			while(dptr < dlen){
        let len = 0
				let seq = secret[sptr++]
				sptr = sptr >= slen ? sptr - slen : sptr
				let shift = 0
				let state, chunk
				while(mask >> shift) {
					let step = (seq & (mask >> shift)) >> (6 - shift)
					if(step) {
						if(!len) {
							len = dlen - dptr < step ? dlen - dptr : step;
							chunk = data.slice(dptr, dptr + len).reduce((value, byte) => (value ? (value << 8) | byte : byte), 0)
							state = origin(chunk, len)
            }
						let key = secret.slice(sptr, sptr + len).reduce((key, byte) => (key ? (key << 8) | byte : byte), 0)
						state = state[fns[step - 1]](key)
						sptr += len
						sptr = sptr >= slen ? sptr - slen : sptr
					}
					shift += 2
				}
				let result = state.done()
    		let part = []
    		let l = len
    		while(l--) {
    			part.unshift(result & 255)
    			result >>= 8
    		}
				encrypted = encrypted.concat(part)
				dptr += len
			}
			if(mode === 'array') return encrypted;
			if(mode === 'bytearray') return Uint8Array.from(encrypted);
			return TextAPI.decode(encrypted)
		}

		this.decrypt = (message, mode = 'text') => {
			const fns = ['sub', 'add', 'xor']
			if(typeof message === 'string') message = TextAPI.encode(message);
			if(message instanceof ArrayBuffer) message = new Uint8Array(message); else
    	if(!(message instanceof Uint8Array)) message = Uint8Array.from(message)
			const data = Uint8Array.from(message)
			const slen = secret.length
			const dlen = data.length
			let decrypted = []
			let sptr = 0
			let dptr = 0
			while(dptr < dlen){
				let len = 0
				let seq = secret[sptr++]
				sptr = sptr >= slen ? sptr - slen : sptr
				let state, chunk
				let shift = 0
				let mask = 192
				let steps = []
				while(mask >> shift) {
					let step = (seq & (mask >> shift)) >> (6 - shift)
					if(step) {
						if(!len) {
							len = dlen - dptr < step ? dlen - dptr : step;
							chunk = data.slice(dptr, dptr + len).reduce((value, byte) => (value ? (value << 8) | byte : byte), 0)
							state = origin(chunk, len)
            }
						let key = secret.slice(sptr, sptr + len).reduce((key, byte) => (key ? (key << 8) | byte : byte), 0)
						steps.unshift({fn: fns[step - 1], key})
						sptr += len
						sptr = sptr >= slen ? sptr - slen : sptr
					}
					shift += 2
				}
				let result = steps.reduce((state, {fn, key}) => state[fn](key), state).done()
	      let part = []
	    	let l = len
	      while(l--) {
	      	part.unshift(result & 255)
	      	result >>= 8
	      }
				decrypted = decrypted.concat(part)
				dptr += len
			}
			if(mode === 'array') return decrypted;
			if(mode === 'bytearray') return Uint8Array.from(decrypted);
			return TextAPI.decode(decrypted)
		}

	}

}
