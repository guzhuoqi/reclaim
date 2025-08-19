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

// 🏦 获取银行兼容的TLS配置（优化版，避免400错误）
export function getBankCompatibleTlsOptions(): TLSConnectionOptions {
	return {
		// 🔧 修复HSBC 400错误：强制使用TLS1.2，避免TLS1.3指纹检测
		supportedProtocolVersions: ['TLS1_2'],
		// 🔧 使用更保守的密码套件选择，只使用TLS1.2套件（更接近curl行为）
		cipherSuites: [
			// 只使用TLS1.2套件，完全避免TLS1.3
			'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',  // 银行最常用
			'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
			'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
			'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
			// 完全移除所有TLS1.3套件，避免指纹检测
		],
		// 🔧 使用更保守的椭圆曲线，避免X25519（可能被检测）
		namedCurves: ['SECP256R1', 'SECP384R1'],
		// 🔧 强制HTTP/1.1，避免协议协商和转换问题
		applicationLayerProtocols: ['http/1.1'],
		// 🏦 模拟curl的TLS行为特征（更多配置可能需要在更底层实现）
	}
}