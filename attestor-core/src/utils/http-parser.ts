import { concatenateUint8Arrays, strToUint8Array } from '@reclaimprotocol/tls'
import type { IncomingHttpHeaders } from 'http'
import type { ArraySlice, Transcript } from 'src/types'
import { findIndexInUint8Array, uint8ArrayToStr } from 'src/utils/generics'
import { REDACTION_CHAR_CODE } from 'src/utils/redactions'

export type HttpRequest = {
    method: string
    url: string
    protocol: string
    headers: IncomingHttpHeaders
    body?: Uint8Array
}

export type HttpResponse = {
    statusCode: number
    statusMessage: string
    headers: IncomingHttpHeaders
    body: Uint8Array
    headersComplete: boolean
    complete: boolean

    /**
     * Index of the first byte of the status line
     */
    statusLineEndIndex?: number
    /**
     * Index of the first byte of the body
     * in the complete response
     */
    bodyStartIndex?: number
    /**
     * If using chunked transfer encoding,
     * this will be set & contain indices of each
     * chunk in the complete response
     */
    chunks?: ArraySlice[]

    headerIndices: Map<string, ArraySlice>
	/**
	 * index of separator \r\n\r\n between headers and body
	 */
	headerEndIdx: number
}

const HTTP_HEADER_LINE_END = strToUint8Array('\r\n')

/**
 * parses http/1.1 responses
 */
export function makeHttpResponseParser() {
	/** the HTTP response data */
	const res: HttpResponse = {
		statusCode: 0,
		statusMessage: '',
		headers: {},
		body: new Uint8Array(),
		complete: false,
		headersComplete: false,
		headerIndices:new Map<string, ArraySlice>(),
		headerEndIdx: 0
	}

	let remainingBodyBytes = 0
	let isChunked = false
	let remaining = new Uint8Array()
	let currentByteIdx = 0

	return {
		res,
		/**
         * Parse the next chunk of data
         * @param data the data to parse
         */
		onChunk(data: Uint8Array) {
			// 🏦 DEBUG: 精简的数据接收日志
			if (data.length > 0) {
				console.log(`📨 接收: ${data.length}字节`)
			}
			
			// concatenate the remaining data from the last chunk
			remaining = concatenateUint8Arrays([remaining, data])
			
			// if we don't have the headers yet, keep reading lines
			// as each header is in a line
			if(!res.headersComplete) {
				for(let line = getLine(); typeof line !== 'undefined'; line = getLine()) {
					// first line is the HTTP version, status code & message
					if(!res.statusCode) {
						const [, statusCode, statusMessage] = line.match(/HTTP\/\d\.\d (\d+) (.*)/) || []
						res.statusCode = Number(statusCode)
						res.statusMessage = statusMessage
						res.statusLineEndIndex = currentByteIdx - HTTP_HEADER_LINE_END.length
					} else if(line === '') { // empty line signifies end of headers
						res.headersComplete = true
						res.headerEndIdx = currentByteIdx - 4
						// if the response is chunked, we need to process the body differently
						if(res.headers['transfer-encoding']?.includes('chunked')) {
							isChunked = true
							res.chunks = []
							break
							// if the response has a content-length, we know how many bytes to read
						} else if(res.headers['content-length']) {
							remainingBodyBytes = Number(res.headers['content-length'])
							break
						} else {
							remainingBodyBytes = -1
							break
							// otherwise,
							// no content-length, no chunked transfer encoding
							// means wait till the stream ends
							// https://stackoverflow.com/a/11376887
						}
					} else if(!res.complete) { // parse the header
						const [key, value] = line.split(': ')
						res.headers[key.toLowerCase()] = value
						res.headerIndices[key.toLowerCase()] = {
							fromIndex:currentByteIdx - line.length - HTTP_HEADER_LINE_END.length,
							toIndex:currentByteIdx - HTTP_HEADER_LINE_END.length
						}
					} else {
						throw new Error('got more data after response was complete')
					}
				}
			}

			if(res.headersComplete) {
				if(remainingBodyBytes) {
					readBody()
					// if no more body bytes to read,
					// and the response was not chunked we're done
					if(!remainingBodyBytes && !isChunked) {
						res.complete = true
					}
				}

				if(res.headers['content-length'] === '0') {
					res.complete = true
				}

				if(isChunked) {
					for(let line = getLine(); typeof line !== 'undefined'; line = getLine()) {
						if(line === '') {
							continue
						}

						const chunkSize = Number.parseInt(line, 16)
						// if chunk size is 0, we're done
						if(!chunkSize) {
							res.complete = true
							continue
						}

						res.chunks?.push({
							fromIndex: currentByteIdx,
							toIndex: currentByteIdx + chunkSize,
						})

						// otherwise read the chunk
						remainingBodyBytes = chunkSize
						readBody()

						// if we read all the data we had,
						// but there's still data left,
						// break the loop and wait for the next chunk
						if(remainingBodyBytes) {
							break
						}
					}
				}
			}
		},
		/**
         * Call to prevent further parsing; indicating the end of the request
         * Checks that the response is valid & complete, otherwise throws an error
         */
		streamEnded() {
			// 🏦 DEBUG: 详细的流状态分析
			console.log(`📥 流结束: headers=${res.headersComplete}, 数据=${remaining.length}字节, status=${res.statusCode || 'NONE'}`)

			if(!res.headersComplete) {
				// 🔍 DEBUG: 打印实际收到的原始数据
				console.log('🔍 DEBUG: 原始数据分析')
				console.log(`   数据长度: ${remaining.length}字节`)
				if (remaining.length > 0) {
					console.log(`   数据内容(hex): ${Array.from(remaining.slice(0, Math.min(100, remaining.length))).map(b => b.toString(16).padStart(2, '0')).join(' ')}`)
					console.log(`   数据内容(text): ${new TextDecoder('utf-8', {fatal: false}).decode(remaining.slice(0, Math.min(100, remaining.length)))}`)
					console.log(`   是否包含HTTP: ${new TextDecoder('utf-8', {fatal: false}).decode(remaining).includes('HTTP')}`)
				}
				throw new Error('stream ended before headers were complete')
			}

			if(remaining.length) {
				throw new Error('stream ended before remaining data arrived')
			}

			if(remainingBodyBytes > 0) {
				throw new Error('stream ended before all body bytes were received')
			}

			res.complete = true
		}
	}

	function readBody() {
		if(res.complete) {
			throw new Error('got more data after response was complete')
		}

		if(!res.bodyStartIndex) {
			res.bodyStartIndex = currentByteIdx
		}

		let bytesToCopy: number
		if(remainingBodyBytes === -1) {
			// all bytes are body bytes
			bytesToCopy = remaining.length
		} else {
			// take the number of bytes we need to read, or the number of bytes remaining
			// and append to the bytes of the body
			bytesToCopy = Math.min(remainingBodyBytes, remaining.length)
			remainingBodyBytes -= bytesToCopy
		}

		res.body = concatenateUint8Arrays([
			res.body,
			remaining.slice(0, bytesToCopy)
		])
		remaining = remaining.slice(bytesToCopy)
		currentByteIdx += bytesToCopy
	}

	function getLine() {
		// find end of line, if it exists
		// otherwise return undefined
		const idx = findIndexInUint8Array(remaining, HTTP_HEADER_LINE_END)
		if(idx === -1) {
			return undefined
		}

		const line = uint8ArrayToStr(remaining.slice(0, idx))
		remaining = remaining.slice(idx + HTTP_HEADER_LINE_END.length)

		currentByteIdx += idx + HTTP_HEADER_LINE_END.length

		return line
	}
}

/**
 * Read the HTTP request from a TLS receipt transcript.
 * @param receipt the transcript to read from or application messages if they were extracted beforehand
 * @returns the parsed HTTP request
 */
export function getHttpRequestDataFromTranscript(receipt: Transcript<Uint8Array>) {
	const clientMsgs = receipt
		.filter(s => s.sender === 'client')

	// 🔍 调试：详细分析第一个客户端消息
	console.log(`🔍 DEBUG TLS Transcript分析:`)
	console.log(`   客户端消息总数: ${clientMsgs.length}`)

	if(clientMsgs.length > 0) {
		const firstMsg = clientMsgs[0]
		console.log(`   第一个消息长度: ${firstMsg.message.length}`)
		console.log(`   第一个字节: ${firstMsg.message[0]} (ASCII: ${String.fromCharCode(firstMsg.message[0])})`)
		console.log(`   REDACTION_CHAR_CODE: ${REDACTION_CHAR_CODE} (ASCII: ${String.fromCharCode(REDACTION_CHAR_CODE)})`)
		console.log(`   前20字节: ${Array.from(firstMsg.message.slice(0, 20)).map(b => String.fromCharCode(b)).join('')}`)
		console.log(`   前20字节(hex): ${Array.from(firstMsg.message.slice(0, 20)).map(b => b.toString(16).padStart(2, '0')).join(' ')}`)

		// 检查是否有任何非redacted的内容
		const nonRedactedBytes = Array.from(firstMsg.message).filter(b => b !== REDACTION_CHAR_CODE)
		console.log(`   非redacted字节数: ${nonRedactedBytes.length}/${firstMsg.message.length}`)

		if(nonRedactedBytes.length > 0) {
			console.log(`   部分非redacted内容: ${nonRedactedBytes.slice(0, 50).map(b => String.fromCharCode(b)).join('')}`)
		}
	}

	// if the first message is redacted, we can't parse it
	// as we don't know what the request was
	if(clientMsgs[0].message[0] === REDACTION_CHAR_CODE) {
		console.log(`❌ 第一个客户端消息被redacted，无法解析`)
		throw new Error('First client message request is redacted. Cannot parse')
	}

	const request: HttpRequest = {
		method: '',
		url: '',
		protocol: '',
		headers: {}
	}
	let requestBuffer = concatenateUint8Arrays(clientMsgs.map(m => m.message))
	// keep reading lines until we get to the end of the headers
	for(let line = getLine(); typeof line !== 'undefined'; line = getLine()) {
		if(line === '') {
			break
		}

		if(!request.method) {
			const [, method, url, protocol] = line.match(/(\w+) (.*) (.*)/) || []
			request.method = method.toLowerCase()
			request.url = url
			request.protocol = protocol
		} else {
			let keyIdx = line.indexOf(':')
			if(keyIdx === -1) {
				keyIdx = line.length - 1
			}

			const key = line.slice(0, keyIdx)
				.toLowerCase()
				.trim()
			const value = line.slice(keyIdx + 1)
				.trim()
			const oldValue = request.headers[key]
			if(typeof oldValue === 'string') {
				request.headers[key] = [oldValue, value]
			} else if(Array.isArray(oldValue)) {
				oldValue.push(value)
			} else {
				request.headers[key] = value
			}
		}
	}

	//the rest is request body
	if(requestBuffer.length) {
		request.body = requestBuffer
	}

	if(!request.method) {
		throw new Error('Client request is incomplete')
	}

	return request

	function getLine() {
		const idx = findIndexInUint8Array(requestBuffer, HTTP_HEADER_LINE_END)
		if(idx === -1) {
			return undefined
		}

		const line = uint8ArrayToStr(requestBuffer.slice(0, idx))
		requestBuffer = requestBuffer
			.slice(idx + HTTP_HEADER_LINE_END.length)

		return line
	}
}