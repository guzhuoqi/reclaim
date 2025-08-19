import { areUint8ArraysEqual, concatenateUint8Arrays, strToUint8Array, TLSConnectionOptions } from '@reclaimprotocol/tls'
import { base64 } from 'ethers/lib/utils'
import { DEFAULT_HTTPS_PORT, RECLAIM_USER_AGENT } from 'src/config'
import { getBankCompatibleTlsOptions } from 'src/utils/tls'  // 🏦 导入银行兼容TLS配置
import { createHTTP2HeadersFrame, isHTTP2Protocol, parseHTTP1Request } from 'src/utils/http2-adapter'  // 🔧 HTTP/2支持
import { AttestorVersion } from 'src/proto/api'
import {
	buildHeaders,
	convertResponsePosToAbsolutePos,
	extractHTMLElementsIndexes,
	extractJSONValueIndexes, getRedactionsForChunkHeaders,
	makeRegex,
	matchRedactedStrings,
	parseHttpResponse,
} from 'src/providers/http/utils'
import { ArraySlice, Provider, ProviderCtx, ProviderParams, ProviderSecretParams, RedactedOrHashedArraySlice } from 'src/types'
import {
	findIndexInUint8Array,
	getHttpRequestDataFromTranscript, logger,
	REDACTION_CHAR_CODE,
	uint8ArrayToBinaryStr,
	uint8ArrayToStr,
} from 'src/utils'

const OK_HTTP_HEADER = 'HTTP/1.1 200'
const dateHeaderRegex = '[dD]ate: ((?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), (?:[0-3][0-9]) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (?:[0-9]{4}) (?:[01][0-9]|2[0-3])(?::[0-5][0-9]){2} GMT)'
const dateDiff = 1000 * 60 * 10 // allow 10 min difference

type HTTPProviderParams = ProviderParams<'http'>

type HTTPResponseRedaction = Exclude<HTTPProviderParams['responseRedactions'], undefined>[number]

const HTTP_PROVIDER: Provider<'http'> = {
	hostPort: getHostPort,
	writeRedactionMode(params) {
		return ('writeRedactionMode' in params)
			? params.writeRedactionMode
			: undefined
	},
	geoLocation(params, secretParams) {
		return ('geoLocation' in params)
			? getGeoLocation(params, secretParams)
			: undefined
	},
	additionalClientOptions(params): TLSConnectionOptions {
		// 🏦 银行兼容性：检测银行URL并使用特殊TLS配置
		const isCMBWingLungBank = params.url?.includes('cmbwinglungbank.com')
		const isHSBCBank = params.url?.includes('hsbc.com.hk')

		let defaultOptions: TLSConnectionOptions = {
			applicationLayerProtocols : ['http/1.1']
		}

		// 🏦 如果是招商永隆银行，使用Chrome兼容的TLS配置
		if (isCMBWingLungBank) {
			defaultOptions = {
				...defaultOptions,
				...getBankCompatibleTlsOptions()
			}
			console.log(`🏦 应用银行兼容TLS配置 - CMB永隆`)
		}

		// 🏦 如果是HSBC银行，也使用Chrome兼容的TLS配置
		if (isHSBCBank) {
			defaultOptions = {
				...defaultOptions,
				...getBankCompatibleTlsOptions()
			}
			console.log(`🏦 应用银行兼容TLS配置 - HSBC`)
		}

		if('additionalClientOptions' in params) {
			defaultOptions = {
				...defaultOptions,
				...params.additionalClientOptions
			}
		}

		return defaultOptions
	},


	createRequest(secretParams, params, logger, selectedAlpn?) {
		// 🍪 修复：适应独立cookie headers格式，不再强制要求cookieStr
		const hasCookies = secretParams.cookieStr || (secretParams.headers && Object.keys(secretParams.headers).some(k => k.toLowerCase() === 'cookie'))
		if(
			!hasCookies &&
            !secretParams.authorisationHeader &&
            !secretParams.headers
		) {
			throw new Error('auth parameters are not set')
		}

		// 🔍 参考001.json格式打印ATTESTOR-CORE接收到的参数（用于与原始请求比对）
		console.log('[ATTESTOR] ===== REQUEST BEGIN (attestor-core) =====')
		console.log(`[ATTESTOR_REQUEST_METHOD] ${params.method}`)
		console.log(`[ATTESTOR_REQUEST_URL] ${params.url}`)
		
		// 统计所有headers数量（包括公开和私密的）
		const pubHeaders = params.headers || {}
		const secHeadersCount = secretParams.headers ? Object.keys(secretParams.headers).length : 0
		// 🍪 修复：适应独立cookie headers，不再单独统计cookieStr
		const cookieCount = secretParams.cookieStr ? 1 : 0
		const authCount = secretParams.authorisationHeader ? 1 : 0
		const totalHeadersCount = Object.keys(pubHeaders).length + secHeadersCount + cookieCount + authCount
		console.log(`[ATTESTOR_REQUEST_HEADERS_COUNT] ${totalHeadersCount}`)
		
		// 打印所有公开headers
		Object.entries(pubHeaders).forEach(([key, value]) => {
			console.log(`[ATTESTOR_REQUEST_HEADER] ${key}: ${value}`)
		})
		
		// 打印所有私密headers
		if (secretParams.headers) {
			Object.entries(secretParams.headers).forEach(([key, value]) => {
				console.log(`[ATTESTOR_REQUEST_HEADER] ${key}: ${value}`)
			})
		}
		
		// 打印Authorization header
		if (secretParams.authorisationHeader) {
			console.log(`[ATTESTOR_REQUEST_HEADER] authorization: ${secretParams.authorisationHeader}`)
		}
		
		// 打印Cookie（解码后的完整内容）
		if (secretParams.cookieStr) {
			try {
				const decodedCookie = Buffer.from(secretParams.cookieStr, 'base64').toString('utf-8')
				console.log(`[ATTESTOR_REQUEST_HEADER] cookie: ${decodedCookie}`)
			} catch (error) {
				console.log(`[ATTESTOR_REQUEST_HEADER] cookie: ${secretParams.cookieStr}`)
			}
		}
		
		// 打印Body信息
		const bodyContent = params.body || ''
		const bodyLength = typeof bodyContent === 'string' ? bodyContent.length : bodyContent.length
		console.log(`[ATTESTOR_REQUEST_BODY_LEN] ${bodyLength}`)
		if (bodyLength > 0) {
			try {
				const bodyStr = typeof bodyContent === 'string' ? bodyContent : new TextDecoder().decode(bodyContent)
				const bodyB64 = Buffer.from(bodyStr, 'utf-8').toString('base64')
				console.log(`[ATTESTOR_REQUEST_BODY_B64] ${bodyB64}`)
			} catch (error) {
				console.log(`[ATTESTOR_REQUEST_BODY_B64] <encoding-error>`)
			}
		} else {
			console.log(`[ATTESTOR_REQUEST_BODY_B64] `)
		}
		
		console.log('[ATTESTOR] ===== REQUEST END (attestor-core) =====')
		
		// 保留原有的简化调试信息
		console.log(`🔍 ATTESTOR-CORE总headers数: ${totalHeadersCount} (公开: ${Object.keys(pubHeaders).length}, 私密: ${secHeadersCount + cookieCount + authCount})`)

		const secHeaders = { ...secretParams.headers }
	// 🍪 修复：禁用旧cookieStr处理，只使用独立cookie headers格式
	if(secretParams.cookieStr) {
		console.log('🍪 检测到旧cookieStr格式，但已禁用（使用独立cookie headers）')
	}
	// 🍪 新格式：独立cookie headers已经在secretParams.headers中，无需额外处理
	console.log('🍪 使用独立cookie headers格式')

		if(secretParams.authorisationHeader) {
			secHeaders['Authorization'] = secretParams.authorisationHeader
		}

		// 🔧 简化：删除银行特殊逻辑，User-Agent由MITM层统一处理
		const hasUserAgent = Object.keys(pubHeaders)
			.some(k => k.toLowerCase() === 'user-agent') ||
            Object.keys(secHeaders)
            	.some(k => k.toLowerCase() === 'user-agent')
		if(!hasUserAgent) {
			pubHeaders['User-Agent'] = RECLAIM_USER_AGENT
			logger.warn('No User-Agent provided - request may be blocked by some services')
		}

		const newParams = substituteParamValues(params, secretParams)
		params = newParams.newParams

		const url = new URL(params.url)
		const { pathname } = url
		const searchParams = params.url.includes('?') ? params.url.split('?')[1] : ''
		logger.info({ url: params.url, path: pathname, query: searchParams.toString() })
		const body =
            params.body instanceof Uint8Array
            	? params.body
            	: strToUint8Array(params.body || '')
		const contentLength = body.length
		const reqLine = `${params.method} ${pathname}${searchParams?.length ? '?' + searchParams : ''} HTTP/1.1`
		const secHeadersList = buildHeaders(secHeaders)
		logger.info({ requestLine: reqLine })
		
		// 🔍 DEBUG: 检查secHeadersList中是否包含priority
		console.log(`🔍 DEBUG secHeadersList (${secHeadersList.length}个):`)
		secHeadersList.forEach((header, i) => {
			if (header.toLowerCase().includes('priority')) {
				console.log(`   [${i}] ${header} ← 发现secHeadersList中的priority!`)
			} else if (i < 3 || i >= secHeadersList.length - 3) {
				console.log(`   [${i}] ${header.substring(0, 50)}...`)
			} else if (i === 3) {
				console.log(`   ... (省略${secHeadersList.length - 6}个) ...`)
			}
		})

		// 简化：直接处理headers，cookie问题已在mitmproxy层修复
		// 🔧 修复：重建headers顺序，确保priority在最后（学习001.json成功模式）
		const orderedHeaders: string[] = []
		const cookieValues: string[] = []
		let priorityHeader: string | null = null

		// 处理所有headers，但特殊处理priority和cookie
		const processHeaders = (headers: any, isSecret = false) => {
			Object.entries(headers).forEach(([key, value]) => {
				let cleanValue = value as string
				const expectedPrefix = `${key}:`

				// 去掉重复前缀（如果存在）
				if (cleanValue.toLowerCase().startsWith(expectedPrefix.toLowerCase())) {
					cleanValue = cleanValue.substring(expectedPrefix.length).trim()
				}
				
				const keyLower = key.toLowerCase()
				
				// 过滤技术性headers (学习001.json成功模式)
				if (keyLower === 'connection' || keyLower === 'host' || keyLower === 'content-length') {
					console.log(`🔧 过滤技术性header: ${key}`)
					return
				}
				
				// 🔧 特殊处理：priority header保留到最后
				if (keyLower === 'priority') {
					if (priorityHeader) {
						console.log(`⚠️ 警告: 发现重复的priority header!`)
						console.log(`   已保留: ${priorityHeader}`)
						console.log(`   新发现: ${key}: ${cleanValue}`)
						console.log(`   来源: ${isSecret ? 'secHeaders' : 'pubHeaders'}`)
						return // 跳过重复的
					}
					priorityHeader = `${key}: ${cleanValue}`
					console.log(`🔧 保留priority header到最后: ${cleanValue} (来源: ${isSecret ? 'secHeaders' : 'pubHeaders'})`)
					return
				}
				
				// 🍪 收集cookie headers
				if (keyLower === 'cookie' || keyLower.startsWith('cookie-')) {
					cookieValues.push(cleanValue)
					console.log(`🍪 收集cookie值: ${cleanValue.substring(0, 50)}...`)
					return
				}
				
				// 添加常规header
				const headerStr = `${key}: ${cleanValue}`
				orderedHeaders.push(headerStr)
			})
		}

		// 先处理公开headers
		processHeaders(pubHeaders)
		// 再处理私密headers
		processHeaders(secHeaders, true)
		
		// 🍪 按顺序添加所有cookie headers
		cookieValues.forEach((value, index) => {
			const cookieHeaderStr = `Cookie: ${value}`
			orderedHeaders.push(cookieHeaderStr)
			console.log(`🍪 设置cookie[${index}]: ${value.substring(0, 50)}...`)
		})
		
		// 🔧 最后添加priority header（学习001.json成功模式）
		if (priorityHeader) {
			orderedHeaders.push(priorityHeader)
			console.log(`🔧 最后添加priority header`)
		}
		
		console.log(`🔧 ✅ 重建 ${orderedHeaders.length} 个headers（${cookieValues.length}个cookie），priority在最后`)

		console.log(`🔍 ATTESTOR-CORE总headers数: ${orderedHeaders.length} (${cookieValues.length}个cookie)`)

		// 🔧 构建最终的HTTP请求（使用有序headers，确保priority在最后）
		const allHeaders = [reqLine, ...orderedHeaders]

		const httpReqHeaderStr = [
			...allHeaders,
			'\r\n',
		].join('\r\n')
		
		// 🔍 DEBUG: 打印最终HTTP请求的前15行和最后5行，确认顺序
		const requestLines = httpReqHeaderStr.split('\r\n')
		console.log(`🔍 DEBUG 最终HTTP请求结构 (${requestLines.length-1}行):`)
		console.log(`   前15行:`)
		requestLines.slice(0, 15).forEach((line, i) => {
			if (line.trim()) console.log(`     ${i+1}: ${line}`)
		})
		console.log(`   ...`)
		console.log(`   最后5行:`)
		const lastLines = requestLines.slice(-6, -1) // 排除最后的空行
		lastLines.forEach((line, i) => {
			const lineNum = requestLines.length - 6 + i
			if (line.trim()) console.log(`     ${lineNum}: ${line}`)
		})
		const headerStr = strToUint8Array(httpReqHeaderStr)
		let data = concatenateUint8Arrays([headerStr, body])
		
		// 🔧 HTTP/2协议适配
		if (isHTTP2Protocol(selectedAlpn)) {
			console.log(`🌐 检测到HTTP/2协议，转换请求格式...`)
			
			try {
				// 解析HTTP/1.1请求
				const { method, path, authority, headers } = parseHTTP1Request(httpReqHeaderStr)
				
				// 🔧 如果authority为空，从参数中获取主机名
				let finalAuthority = authority
				if (!finalAuthority && url) {
					try {
						const urlObj = new URL(url)
						finalAuthority = urlObj.host
						console.log(`🔧 从URL提取Authority: ${finalAuthority}`)
					} catch (e) {
						console.warn(`⚠️ 无法从URL提取Authority: ${url}`)
					}
				}
				
				// 创建HTTP/2 HEADERS帧
				const http2Frame = createHTTP2HeadersFrame(headers, method, path, finalAuthority, 1)
				
				console.log(`🔧 HTTP/2转换完成: ${method} ${path}`)
				console.log(`   Authority: ${finalAuthority}`)
				console.log(`   Headers数量: ${headers.length}`)
				console.log(`   Frame长度: ${http2Frame.length}字节`)
				
				// 使用HTTP/2帧替换原始数据
				data = http2Frame
			} catch (error) {
				console.error(`❌ HTTP/2转换失败:`, error)
				console.log(`🔄 降级使用HTTP/1.1格式`)
			}
		} else {
			console.log(`🌐 使用HTTP/1.1协议`)
		}



		// hide all secret headers
		const secHeadersStr = secHeadersList.join('\r\n')
		const tokenStartIndex = findIndexInUint8Array(
			data,
			strToUint8Array(secHeadersStr)
		)

		const redactions = [
			{
				fromIndex: tokenStartIndex,
				toIndex: tokenStartIndex + secHeadersStr.length,
			}
		]

		if(newParams.hiddenBodyParts?.length > 0) {
			for(const hiddenBodyPart of newParams.hiddenBodyParts) {
				if(hiddenBodyPart.length) {
					redactions.push({
						fromIndex: headerStr.length + hiddenBodyPart.index,
						toIndex: headerStr.length + hiddenBodyPart.index + hiddenBodyPart.length,
					})
				}
			}
		}

		if(newParams.hiddenURLParts?.length > 0) {
			for(const hiddenURLPart of newParams.hiddenURLParts) {
				if(hiddenURLPart.length) {
					redactions.push({
						fromIndex: hiddenURLPart.index,
						toIndex: hiddenURLPart.index + hiddenURLPart.length,
					})
				}
			}
		}

		redactions.sort((a, b) => a.toIndex - b.toIndex)
		return {
			data,
			redactions: redactions,
		}
	},
	getResponseRedactions({ response, params: rawParams, logger, ctx }) {
		logger.debug({ response:base64.encode(response), params:rawParams })

		const res = parseHttpResponse(response)
		if(!rawParams.responseRedactions?.length) {
			return []
		}

		if(((res.statusCode / 100) >> 0) !== 2) {
			logger.error({ response:base64.encode(response), params:rawParams })
			throw new Error(
				`Expected status 2xx, got ${res.statusCode} (${res.statusMessage})`
			)
		}

		const newParams = substituteParamValues(rawParams, undefined, true)
		const params = newParams.newParams

		const headerEndIndex = res.statusLineEndIndex!
		const bodyStartIdx = res.bodyStartIndex ?? 0
		if(bodyStartIdx < 4) {
			logger.error({ response: uint8ArrayToBinaryStr(response) })
			throw new Error('Failed to find response body')
		}

		const reveals: RedactedOrHashedArraySlice[] = [
			{ fromIndex: 0, toIndex: headerEndIndex }
		]

		//reveal double CRLF which separates headers from body
		if(shouldRevealCrlf(ctx)) {
			const crlfs = response
				.slice(res.headerEndIdx, res.headerEndIdx + 4)
			if(!areUint8ArraysEqual(crlfs, strToUint8Array('\r\n\r\n'))) {
				logger.error({ response: uint8ArrayToBinaryStr(response) })
				throw new Error(
					`Failed to find header/body separator at index ${res.headerEndIdx}`
				)
			}
		}

		reveals.push({ fromIndex:res.headerEndIdx, toIndex:res.headerEndIdx + 4 })

		//reveal date header
		if(res.headerIndices['date']) {
			reveals.push(res.headerIndices['date'])
		}

		const body = uint8ArrayToBinaryStr(res.body)
		const redactions: RedactedOrHashedArraySlice[] = []
		for(const rs of params.responseRedactions || []) {
			const processor = processRedactionRequest(
				body, rs, bodyStartIdx, res.chunks
			)
			for(const { reveal, redactions: reds } of processor) {
				reveals.push(reveal)
				redactions.push(...reds)
			}
		}

		reveals.sort((a, b) => a.toIndex - b.toIndex)

		if(reveals.length > 1) {
			let currentIndex = 0
			for(const r of reveals) {
				if(currentIndex < r.fromIndex) {
					redactions.push({ fromIndex: currentIndex, toIndex: r.fromIndex })
				}

				currentIndex = r.toIndex
			}

			redactions.push({ fromIndex: currentIndex, toIndex: response.length })
		}

		for(const r of reveals) {
			if(!r.hash) {
				continue
			}

			redactions.push(r)
		}

		redactions.sort((a, b) => a.toIndex - b.toIndex)

		return redactions
	},
	assertValidProviderReceipt({ receipt, params: paramsAny, logger, ctx }) {
		logTranscript()
		let extractedParams: { [_: string]: string } = {}
		const secretParams = ('secretParams' in paramsAny)
			? paramsAny.secretParams as ProviderSecretParams<'http'>
			: undefined
		const newParams = substituteParamValues(paramsAny, secretParams, !secretParams)
		const params = newParams.newParams
		extractedParams = { ...extractedParams, ...newParams.extractedValues }

		const req = getHttpRequestDataFromTranscript(receipt)

		// 🔍 调试：打印解析后的请求headers
		console.log(`📋 DEBUG 解析后的请求headers:`)
		console.log(`   headers对象:`, JSON.stringify(req.headers, null, 2))
		console.log(`   headers的keys:`, Object.keys(req.headers))
		console.log(`   headers的类型:`, typeof req.headers)

		if(req.method !== params.method.toLowerCase()) {
			throw new Error(`Invalid method: ${req.method}`)
		}

		const url = new URL(params.url)
		const { protocol, pathname } = url

		if(protocol !== 'https:') {
			logger.error('params URL: %s', params.url)
			throw new Error(`Expected protocol: https, found: ${protocol}`)
		}

		const searchParams = params.url.includes('?') ? params.url.split('?')[1] : ''
		//brackets in URL path turn into %7B and %7D, so replace them back
		const expectedPath = pathname.replaceAll('%7B', '{').replaceAll('%7D', '}') + (searchParams?.length ? '?' + searchParams : '')
		if(!matchRedactedStrings(strToUint8Array(expectedPath), strToUint8Array(req.url))) {
			logger.error('params URL: %s', params.url)
			throw new Error(`Expected path: ${expectedPath}, found: ${req.url}`)
		}

			const expectedHostStr = getHostHeaderString(url)
		// if(req.headers.host !== expectedHostStr) {
		// 	throw new Error(`Expected host: ${expectedHostStr}, found: ${req.headers.host}`)
		// }

		// // 🔧 简化：删除银行特殊的Connection验证逻辑
		// const connectionHeader = req.headers['connection']
		// console.log(`🔗 DEBUG Connection头: "${connectionHeader}" (类型: ${typeof connectionHeader})`)

		// // 简化验证：只检查close连接（MITM层已确保正确设置）
		// if(connectionHeader && connectionHeader !== 'close' && connectionHeader !== 'keep-alive') {
		// 	throw new Error(`Unexpected connection header: "${connectionHeader}"`)
		// }

		const serverBlocks = receipt
			.filter(s => s.sender === 'server')
			.map((r) => r.message)
			.filter(b => !b.every(b => b === REDACTION_CHAR_CODE)) // filter out fully redacted blocks
		const response = concatArrays(...serverBlocks)

		let res: string
		res = uint8ArrayToStr(response)

		const okRegex = makeRegex('^HTTP\\/1.1 2\\d{2}')
		const matchRes = okRegex.exec(res)
		if(!matchRes) {
			const statusRegex = makeRegex('^HTTP\\/1.1 (\\d{3})')
			const matchRes = statusRegex.exec(res)
			if(matchRes && matchRes.length > 1) {
				// 🔍 提取详细错误信息（增加更多行和字符限制用于CloudFront分析）
				let errorDetails = ''
				const lines = res.split('\n')
				
				// 提取前20行的响应头和内容
				for (let i = 0; i < Math.min(20, lines.length); i++) {
					const line = lines[i].replace(/\*/g, '') // 移除redaction字符
					if (line.trim()) {
						errorDetails += line.trim() + ' | '
					}
				}
				
				if (errorDetails.length > 1000) {
					errorDetails = errorDetails.substring(0, 1000) + '...'
				}
				
				throw new Error(
					`Provider returned error ${matchRes[1]} - ${errorDetails}`
				)
			}

			let lineEnd = res.indexOf('*')
			if(lineEnd === -1) {
				lineEnd = res.indexOf('\n')
			}

			if(lineEnd === -1) {
				lineEnd = OK_HTTP_HEADER.length
			}

			throw new Error(
				`Response did not start with \"HTTP/1.1 2XX\" got "${res.slice(0, lineEnd)}"`
			)
		}

		let bodyStart: number
		if(shouldRevealCrlf(ctx)) {
			bodyStart = res.indexOf('\r\n\r\n', OK_HTTP_HEADER.length) + 4
			if(bodyStart < 4) {
				throw new Error('Response body start not found')
			}
		} else {
			bodyStart = OK_HTTP_HEADER.length
		}

		//validate server Date header if present
		const dateHeader = makeRegex(dateHeaderRegex).exec(res)
		if(dateHeader?.length > 1) {
			const serverDate = new Date(dateHeader[1])
			if((Date.now() - serverDate.getTime()) > dateDiff) {

				logger.info({ dateHeader:dateHeader[0], current: Date.now() }, 'date header is off')

				throw new Error(
					`Server date is off by "${(Date.now() - serverDate.getTime()) / 1000} s"`
				)
			}
		}


		const paramBody = params.body instanceof Uint8Array
			? params.body
			: strToUint8Array(params.body || '')

		if(paramBody.length > 0 && !matchRedactedStrings(paramBody, req.body)) {
			throw new Error('request body mismatch')
		}


		//remove asterisks to account for chunks in the middle of revealed strings
		if(!secretParams) {
			res = res.slice(bodyStart).replace(/(\*){3,}/g, '')
		}

		// 🔍 调试：打印解密的应答内容
		console.log(`📄 DEBUG 解密的应答内容分析:`)
		console.log(`   应答长度: ${res.length}`)
		console.log(`   应答前500字符: ${JSON.stringify(res.slice(0, 500))}`)
		console.log(`   应答后500字符: ${JSON.stringify(res.slice(-500))}`)
		console.log(`   responseMatches数量: ${params.responseMatches?.length || 0}`)

		for(const { type, value, invert } of params.responseMatches || []) {
			const inv = Boolean(invert) // explicitly cast to boolean

			switch (type) {
			case 'regex':
				console.log(`🔍 DEBUG 测试正则表达式: "${value}"`)
				const regexRes = makeRegex(value).exec(res)
				const match = regexRes !== null
				console.log(`   匹配结果: ${match}`)

				if(match) {
					console.log(`   匹配内容: ${JSON.stringify(regexRes)}`)
					const groups = regexRes?.groups
					console.log(`   命名捕获组: ${JSON.stringify(groups)}`)
				}

				if(match === inv) { // if both true or both false then fail
					console.log(`❌ 正则表达式验证失败: match=${match}, invert=${inv}`)
					throw new Error(
						'Invalid receipt.'
						+ ` Regex "${value}" ${invert ? 'matched' : "didn't match"}`
					)
				}

				if(!match) {
					console.log(`⚠️ 正则表达式未匹配，跳过`)
					continue
				}

				const groups = regexRes?.groups
				for(const paramName in groups || []) {
					if(paramName in extractedParams) {
						throw new Error(`Duplicate parameter ${paramName}`)
					}

					extractedParams[paramName] = groups[paramName]
					console.log(`✅ 提取参数: ${paramName} = "${groups[paramName]}"`)
				}

				break
			case 'contains':
				const includes = res.includes(value)
				if(includes === inv) {
					throw new Error(
						`Invalid receipt. Response ${invert ? 'contains' : 'does not contain'} "${value}"`
					)
				}

				break
			default:
				throw new Error(`Invalid response match type ${type}`)
			}
		}

		function concatArrays(...bufs: Uint8Array[]) {
			const totalSize = bufs.reduce((acc, e) => acc + e.length, 0)
			const merged = new Uint8Array(totalSize)

			let lenDone = 0
			for(const array of bufs) {
				merged.set(array, lenDone)
				lenDone += array.length
			}

			return merged

		}

		// 🔍 调试：总结提取的参数
		console.log(`📊 DEBUG 参数提取总结:`)
		console.log(`   提取的参数数量: ${Object.keys(extractedParams).length}`)
		console.log(`   提取的参数: ${JSON.stringify(extractedParams, null, 2)}`)

		if(Object.keys(extractedParams).length === 0) {
			console.log(`⚠️ 警告: 没有提取到任何参数！`)
			console.log(`   可能原因:`)
			console.log(`   1. 正则表达式与实际响应内容不匹配`)
			console.log(`   2. 响应内容格式与预期不符`)
			console.log(`   3. 命名捕获组配置有问题`)
		}

		console.log(`🎯 DEBUG 返回extractedParameters: ${JSON.stringify({ extractedParameters: extractedParams })}`)
		return { extractedParameters: extractedParams }

		function logTranscript() {
			const clientMsgs = receipt.filter(s => s.sender === 'client').map(m => m.message)
			const serverMsgs = receipt.filter(s => s.sender === 'server').map(m => m.message)

			const clientTranscript = base64.encode(concatenateUint8Arrays(clientMsgs))
			const serverTranscript = base64.encode(concatenateUint8Arrays(serverMsgs))

			logger.debug({ request: clientTranscript, response:serverTranscript, params:paramsAny })
		}
	},
}

// revealing CRLF is a breaking change -- and should only be done
// if the client's version supports it
function shouldRevealCrlf({ version }: ProviderCtx) {
	return version >= AttestorVersion.ATTESTOR_VERSION_2_0_1
}

function getHostPort(params: ProviderParams<'http'>, secretParams: ProviderSecretParams<'http'>) {
	const { host } = new URL(getURL(params, secretParams))
	if(!host) {
		throw new Error('url is incorrect')
	}

	return host
}

/**
 * Obtain the host header string from the URL.
 * https://stackoverflow.com/a/3364396
 */
function getHostHeaderString(url: URL) {
	const host = url.hostname
	const port = url.port
	return port && +port !== DEFAULT_HTTPS_PORT
		? `${host}:${port}`
		: host

}

type ReplacedParams = {
    newParam: string
    extractedValues: { [_: string]: string }
    hiddenParts: { index: number, length: number } []
} | null

type RedactionItem = {
	reveal: RedactedOrHashedArraySlice
	redactions: RedactedOrHashedArraySlice[]
}

const paramsRegex = /{{([^{}]+)}}/sgi

function *processRedactionRequest(
	body: string,
	rs: HTTPResponseRedaction,
	bodyStartIdx: number,
	resChunks: ArraySlice[] | undefined,
): Generator<RedactionItem> {
	let element = body
	let elementIdx = 0
	let elementLength = -1

	if(rs.xPath) {
		const indexes = extractHTMLElementsIndexes(body, rs.xPath, !!rs.jsonPath)
		for(const { start, end } of indexes) {
			element = body.slice(start, end)
			elementIdx = start
			elementLength = end - start
			if(rs.jsonPath) {
				yield *processJsonPath()
			} else if(rs.regex) {
				yield *processRegexp()
			} else {
				yield *addRedaction()
			}
		}
	} else if(rs.jsonPath) {
		yield *processJsonPath()
	} else if(rs.regex) {
		yield *processRegexp()
	} else {
		throw new Error(
			'Expected either xPath, jsonPath or regex for redaction'
		)
	}

	function *processJsonPath() {
		const jsonPathIndexes = extractJSONValueIndexes(element, rs.jsonPath!)
		// eslint-disable-next-line max-depth
		const eIndex = elementIdx
		for(const ji of jsonPathIndexes) {
			const jStart = ji.start
			const jEnd = ji.end
			element = body.slice(eIndex + jStart, eIndex + jEnd)
			elementIdx = eIndex + jStart
			elementLength = jEnd - jStart
			// eslint-disable-next-line max-depth
			if(rs.regex) {
				yield *processRegexp()
			} else {
				yield *addRedaction()
			}
		}
	}

	function *processRegexp() {
		logger.debug({ element: base64.encode(strToUint8Array(element)), body: base64.encode(strToUint8Array(body)) })
		const regexp = makeRegex(rs.regex!)
		const elem = element || body
		const match = regexp.exec(elem)
		// eslint-disable-next-line max-depth
		if(!match?.[0]) {

			throw new Error(
				`regexp ${rs.regex} does not match found element '${base64.encode(strToUint8Array(elem))}'`
			)
		}

		elementIdx += match.index
		elementLength = regexp.lastIndex - match.index
		element = match[0]

		if(rs.hash && (!match.groups || Object.keys(match.groups).length > 1)) {
			throw new Error(
				'Exactly one named capture group is needed per hashed redaction'
			)
		}

		// if there are groups in the regex,
		// we'll only hash the group values
		if(!rs.hash || !match.groups) {
			yield *addRedaction()
			return
		}


		const fullStr = match[0]
		const grp = Object.values(match.groups)[0] as string
		const grpIdx = fullStr.indexOf(grp)

		// don't hash the entire regex, we'll hash the group values
		elementLength = grpIdx
		element = fullStr.slice(0, grpIdx)
		yield *addRedaction(null)

		elementIdx += grpIdx
		element = grp
		elementLength = grp.length

		const reveal = getReveal(elementIdx, elementLength, rs.hash)
		const chunkReds = getRedactionsForChunkHeaders(
			reveal.fromIndex,
			reveal.toIndex,
			resChunks
		)
		if(chunkReds.length) {
			throw new Error(
				'Hash redactions cannot be performed if '
				+ 'the redacted string is split between 2'
				+ ' or more HTTP chunks'
			)
		}

		yield { reveal, redactions: chunkReds }

		elementIdx += grp.length
		element = fullStr.slice(grpIdx + grp.length)
		elementLength = element.length
		yield *addRedaction(null)
	}

	// eslint-disable-next-line unicorn/consistent-function-scoping
	function *addRedaction(
		hash: RedactedOrHashedArraySlice['hash'] | null = rs.hash,
		_resChunks = resChunks
	): Generator<RedactionItem> {
		if(elementIdx < 0 || !elementLength) {
			return
		}

		const reveal = getReveal(elementIdx, elementLength, hash || undefined)

		yield {
			reveal,
			redactions: getRedactionsForChunkHeaders(
				reveal.fromIndex,
				reveal.toIndex,
				_resChunks
			)
		}
	}

	function getReveal(
		startIdx: number,
		len: number,
		hash?: RedactedOrHashedArraySlice['hash']
	) {
		const from = convertResponsePosToAbsolutePos(
			startIdx,
			bodyStartIdx,
			resChunks
		)
		const to = convertResponsePosToAbsolutePos(
			startIdx + len,
			bodyStartIdx,
			resChunks
		)

		return { fromIndex: from, toIndex: to, hash }
	}
}

function substituteParamValues(
	currentParams: HTTPProviderParams,
	secretParams?: ProviderSecretParams<'http'>,
	ignoreMissingParams?: boolean
): {
    newParams: HTTPProviderParams
    extractedValues: { [_: string]: string }
    hiddenBodyParts: { index: number, length: number } []
	hiddenURLParts: { index: number, length: number } []
} {

	const params = JSON.parse(JSON.stringify(currentParams))
	let extractedValues: { [_: string]: string } = {}

	const hiddenURLParts: { index: number, length: number } [] = []
	const urlParams = extractAndReplaceTemplateValues(params.url, ignoreMissingParams)
	if(urlParams) {
		params.url = urlParams.newParam
		extractedValues = { ...urlParams.extractedValues }

		if(urlParams.hiddenParts.length) {
			const host = getHostHeaderString(new URL(params.url))
			const offset = `https://${host}`.length - currentParams.method.length - 1 //space between method and start of the path
			for(const hiddenURLPart of urlParams.hiddenParts) {
				hiddenURLParts.push({ index:hiddenURLPart.index - offset, length:hiddenURLPart.length })
			}
		}

	}


	let bodyParams: ReplacedParams
	let hiddenBodyParts: { index: number, length: number } [] = []
	if(params.body) {
		const strBody = typeof params.body === 'string' ? params.body : uint8ArrayToStr(params.body)
		bodyParams = extractAndReplaceTemplateValues(strBody, ignoreMissingParams)
		if(bodyParams) {
			params.body = bodyParams.newParam
			extractedValues = { ...extractedValues, ...bodyParams.extractedValues }
			hiddenBodyParts = bodyParams.hiddenParts
		}

	}

	const geoParams = extractAndReplaceTemplateValues(params.geoLocation)
	if(geoParams) {
		params.geoLocation = geoParams.newParam
		extractedValues = { ...extractedValues, ...geoParams.extractedValues }
	}

	if(params.responseRedactions) {
		for(const r of params.responseRedactions) {
			if(r.regex) {
				const regexParams = extractAndReplaceTemplateValues(r.regex)
				r.regex = regexParams?.newParam
			}

			if(r.xPath) {
				const xpathParams = extractAndReplaceTemplateValues(r.xPath)
				r.xPath = xpathParams?.newParam
			}

			if(r.jsonPath) {
				const jsonPathParams = extractAndReplaceTemplateValues(r.jsonPath)
				r.jsonPath = jsonPathParams?.newParam
			}
		}
	}

	if(params.responseMatches) {
		for(const r of params.responseMatches) {
			if(r.value !== '') {
				const matchParam = extractAndReplaceTemplateValues(r.value)
				r.value = matchParam?.newParam!
				extractedValues = { ...extractedValues, ...matchParam?.extractedValues }
			}
		}
	}

	return {
		newParams: params,
		extractedValues: extractedValues,
		hiddenBodyParts: hiddenBodyParts,
		hiddenURLParts:hiddenURLParts
	}

	function extractAndReplaceTemplateValues(param: string | undefined, ignoreMissingParams?: boolean): ReplacedParams {

		if(!param) {
			return null
		}

		//const paramNames: Set<string> = new Set()
		const extractedValues: { [_: string]: string } = {}
		const hiddenParts: { index: number, length: number }[] = []


		let totalOffset = 0
		param = param.replace(paramsRegex, (match, pn, offset) => {
			if(params.paramValues && pn in params.paramValues) {
				extractedValues[pn] = params.paramValues[pn]
				totalOffset += params.paramValues[pn].length - match.length
				return params.paramValues[pn]
			} else if(secretParams) {
				if(secretParams?.paramValues && pn in secretParams?.paramValues) {
					hiddenParts.push({
						index: offset + totalOffset,
						length: secretParams.paramValues[pn].length,
					})
					totalOffset += secretParams.paramValues[pn].length - match.length
					return secretParams.paramValues[pn]
				} else {
					throw new Error(`parameter's "${pn}" value not found in paramValues and secret parameter's paramValues`)
				}
			} else {
				if(!(!!ignoreMissingParams)) {
					throw new Error(`parameter's "${pn}" value not found in paramValues`)
				} else {
					return match
				}
			}
		})

		return {
			newParam: param,
			extractedValues: extractedValues,
			hiddenParts: hiddenParts
		}
	}
}

function getGeoLocation(v2Params: HTTPProviderParams, secretParams?: ProviderSecretParams<'http'>) {
	if(v2Params?.geoLocation) {
		const paramNames: Set<string> = new Set()
		let geo = v2Params.geoLocation
		//extract param names

		let match: RegExpExecArray | null = null
		while(match = paramsRegex.exec(geo)) {
			paramNames.add(match[1])
		}

		for(const pn of paramNames) {
			if(v2Params.paramValues && pn in v2Params.paramValues) {
				geo = geo?.replaceAll(`{{${pn}}}`, v2Params.paramValues[pn].toString())
			} else if(secretParams?.paramValues && pn in secretParams.paramValues) {
				geo = geo?.replaceAll(`{{${pn}}}`, secretParams.paramValues[pn].toString())
			} else {
				throw new Error(`parameter "${pn}" value not found in templateParams`)
			}
		}

		const geoRegex = /^[A-Za-z]{2}$/sgiu
		if(!geoRegex.test(geo)) {
			throw new Error(`Geolocation ${geo} is invalid`)
		}

		return geo
	}

	return undefined
}

function getURL(v2Params: HTTPProviderParams, secretParams: ProviderSecretParams<'http'>) {
	let hostPort = v2Params?.url
	const paramNames: Set<string> = new Set()

	//extract param names
	let match: RegExpExecArray | null = null
	while(match = paramsRegex.exec(hostPort)) {
		paramNames.add(match[1])
	}

	for(const pn of paramNames) {
		if(v2Params.paramValues && pn in v2Params.paramValues) {
			hostPort = hostPort?.replaceAll(`{{${pn}}}`, v2Params.paramValues[pn].toString())
		} else if(secretParams?.paramValues && pn in secretParams.paramValues) {
			hostPort = hostPort?.replaceAll(`{{${pn}}}`, secretParams.paramValues[pn].toString())
		} else {
			throw new Error(`parameter "${pn}" value not found in templateParams`)
		}
	}

	return hostPort
}




export default HTTP_PROVIDER
