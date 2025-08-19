/**
 * 最小化的HTTP/2适配器
 * 用于将HTTP/1.1格式的请求转换为HTTP/2 HEADERS帧
 */

export interface HTTP2Frame {
	type: number
	flags: number
	streamId: number
	payload: Uint8Array
}

/**
 * 创建HTTP/2 HEADERS帧
 * @param headers HTTP/1.1格式的headers数组
 * @param method HTTP方法
 * @param path URL路径
 * @param authority 主机名
 * @param streamId 流ID（通常是1）
 */
export function createHTTP2HeadersFrame(
	headers: string[],
	method: string,
	path: string,
	authority: string,
	streamId: number = 1
): Uint8Array {
	// 🔧 HTTP/2伪headers（必须放在开头）
	const pseudoHeaders = [
		`:method: ${method}`,
		`:path: ${path}`,
		`:scheme: https`,
		`:authority: ${authority}`,
	]
	
	// 🔧 合并伪headers和普通headers
	const allHeaders = [...pseudoHeaders, ...headers]
	
	// 🔧 简化版HPACK编码：使用未压缩的字面量头部
	// 这不是最优的，但可以工作
	const headerBlocks: Uint8Array[] = []
	
	for (const header of allHeaders) {
		const [name, value] = header.split(': ', 2)
		if (!name || !value) continue
		
		// 使用未压缩字面量头部编码 (0x00前缀)
		const nameBytes = new TextEncoder().encode(name.toLowerCase())
		const valueBytes = new TextEncoder().encode(value)
		
		const block = new Uint8Array(1 + 1 + nameBytes.length + 1 + valueBytes.length)
		let offset = 0
		
		// 字面量头部标记 (0x00)
		block[offset++] = 0x00
		
		// 名称长度 + 名称
		block[offset++] = nameBytes.length
		block.set(nameBytes, offset)
		offset += nameBytes.length
		
		// 值长度 + 值
		block[offset++] = valueBytes.length
		block.set(valueBytes, offset)
		
		headerBlocks.push(block)
	}
	
	// 合并所有header blocks
	const totalLength = headerBlocks.reduce((sum, block) => sum + block.length, 0)
	const payload = new Uint8Array(totalLength)
	let payloadOffset = 0
	
	for (const block of headerBlocks) {
		payload.set(block, payloadOffset)
		payloadOffset += block.length
	}
	
	// 🔧 创建HTTP/2帧头（9字节）
	const frameHeader = new Uint8Array(9)
	
	// Length (24位，大端序)
	frameHeader[0] = (payload.length >> 16) & 0xFF
	frameHeader[1] = (payload.length >> 8) & 0xFF
	frameHeader[2] = payload.length & 0xFF
	
	// Type (HEADERS = 0x01)
	frameHeader[3] = 0x01
	
	// Flags (END_HEADERS = 0x04, 如果没有body也设置END_STREAM = 0x01)
	frameHeader[4] = 0x05  // END_HEADERS | END_STREAM (适用于GET请求)
	
	// Stream ID (31位，大端序)
	frameHeader[5] = (streamId >> 24) & 0x7F  // 最高位必须是0
	frameHeader[6] = (streamId >> 16) & 0xFF
	frameHeader[7] = (streamId >> 8) & 0xFF
	frameHeader[8] = streamId & 0xFF
	
	// 合并帧头和payload
	const frame = new Uint8Array(frameHeader.length + payload.length)
	frame.set(frameHeader, 0)
	frame.set(payload, frameHeader.length)
	
	return frame
}

/**
 * 检测协商的协议是否为HTTP/2
 */
export function isHTTP2Protocol(selectedAlpn?: string): boolean {
	return selectedAlpn === 'h2'
}

/**
 * 从HTTP/1.1请求字符串解析出组件
 */
export function parseHTTP1Request(httpRequest: string): {
	method: string
	path: string
	authority: string
	headers: string[]
} {
	const lines = httpRequest.split('\r\n')
	const requestLine = lines[0]
	
	// 解析请求行 "GET /path HTTP/1.1"
	const [method, fullPath] = requestLine.split(' ')
	
	// 从URL中提取path
	let path = '/'
	let authority = ''
	
	if (fullPath.startsWith('http')) {
		const url = new URL(fullPath)
		path = url.pathname + url.search
		authority = url.host
	} else {
		path = fullPath
	}
	
	// 解析headers，跳过空行
	const headers: string[] = []
	for (let i = 1; i < lines.length && lines[i].trim(); i++) {
		const header = lines[i].trim()
		if (header) {
			// 为HTTP/2提取authority
			if (header.toLowerCase().startsWith('host:') && !authority) {
				authority = header.split(':', 2)[1].trim()
			}
			headers.push(header)
		}
	}
	
	return { method, path, authority, headers }
}
