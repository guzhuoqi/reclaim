import { CipherSuite, SUPPORTED_NAMED_CURVES, TLSConnectionOptions } from '@reclaimprotocol/tls'
import { detectEnvironment } from 'src/utils/env'

// we only support the following cipher suites
// for ZK proof generation
const ZK_CIPHER_SUITES: CipherSuite[] = [
	// chacha-20
	'TLS_CHACHA20_POLY1305_SHA256',
	'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
	'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
	// aes-256
	'TLS_AES_256_GCM_SHA384',
	'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
	'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
	// aes-128
	'TLS_AES_128_GCM_SHA256',
	'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
	'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
]

// 🏦 银行兼容性：模拟Chrome的TLS握手顺序（基于mitmproxy分析）
const CHROME_LIKE_CIPHER_SUITES: CipherSuite[] = [
	// 优先TLS1.3 cipher (Chrome首选)
	'TLS_AES_256_GCM_SHA384',        // mitmproxy显示Chrome使用的
	'TLS_AES_128_GCM_SHA256',
	'TLS_CHACHA20_POLY1305_SHA256',
	// TLS1.2 ECDHE (降级后使用)
	'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',  // 银行实际选择的
	'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
	'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
	'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
	'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
	'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
]

const NAMED_CURVE_LIST = detectEnvironment() === 'node'
	? SUPPORTED_NAMED_CURVES
	// X25519 is not supported in the browser
	: SUPPORTED_NAMED_CURVES.filter(c => c !== 'X25519')

export function getDefaultTlsOptions(): TLSConnectionOptions {
	return {
		cipherSuites: ZK_CIPHER_SUITES,
		namedCurves: NAMED_CURVE_LIST,
	}
}

// 🏦 获取银行兼容的TLS配置
export function getBankCompatibleTlsOptions(): TLSConnectionOptions {
	return {
		cipherSuites: CHROME_LIKE_CIPHER_SUITES,
		namedCurves: NAMED_CURVE_LIST,
		// Chrome的ALPN协议顺序
		applicationLayerProtocols: ['h2', 'http/1.1'],
		// 🏦 模拟Chrome的TLS行为特征（更多配置可能需要在更底层实现）
	}
}