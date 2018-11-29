const BitFilament = require('./bit-filament')
const BitChaos = require('./bit-chaos')

module.exports = function rapi({ lapi, socket, ecdh, getState = () => {}, setState = () => {}}) {

	return new Promise((ok, fail) => {

		const filament = new BitFilament()

		let secret = '', cipher

		socket.binaryType = 'arraybuffer'

		socket.addEventListener('message', ({ data }) => {

			if(!secret) {
				data = new Uint8Array(data)
				const { key, api } = filament.untwist(data).shift()
				secret = ecdh.computeSecret(key)
				cipher = new BitChaos(secret)

				const rapi = {}

				api.forEach(method => rapi[method] = (...args) => {
					const payload = filament.twist([method, ...args])
					socket.send(cipher.encrypt(payload, 'bytearray'))
				})

				lapi = lapi(rapi, getState, setState)

				rapi.key = key

				ok(rapi)

			} else {

				const payload = cipher.decrypt(data, 'bytearray')
				const [ method, ...args ] = filament.untwist(payload).shift()
				if(typeof lapi[method] === 'function') lapi[method](...args);

			}
		})

		const key = ecdh.getPublicKey()
		// console.log('>>>', {key})
		const payload = filament.twist({ key, api: Object.keys(lapi()) })
		// console.log('>>>', {payload})
		socket.send(Uint8Array.from(payload))

	})

}
