#!/usr/bin/env node

/**
 * 专门为 Python 调用设计的 attestor 脚本
 * 只输出纯 JSON，不包含调试信息
 */

// 使用相对路径导入，避免模块解析问题
const path = require('path')
const { createClaimOnAttestor } = require('../client')
const { getAttestorClientFromPool } = require('../client/utils/attestor-pool')

// 创建一个静默的 logger，只输出到 stderr
const logger = {
	trace: (...args) => console.error('[TRACE]', ...args),
	debug: (...args) => console.error('[DEBUG]', ...args),
	info: (...args) => console.error('[INFO]', ...args),
	warn: (...args) => console.error('[WARN]', ...args),
	error: (...args) => console.error('[ERROR]', ...args),
	fatal: (...args) => console.error('[FATAL]', ...args),
	child: () => logger
}

async function main() {
	try {
		// 禁用所有控制台输出到 stdout，只保留我们的 JSON 输出
		const originalConsoleLog = console.log
		const originalConsoleDebug = console.debug
		const originalConsoleInfo = console.info
		const originalConsoleWarn = console.warn

		// 重定向所有 console 输出到 stderr
		console.log = (...args) => console.error('[LOG]', ...args)
		console.debug = (...args) => console.error('[DEBUG]', ...args)
		console.info = (...args) => console.error('[INFO]', ...args)
		console.warn = (...args) => console.error('[WARN]', ...args)

		// 从命令行参数获取配置
		const args = process.argv.slice(2)
		if (args.length < 4) {
			throw new Error('Usage: node generate-receipt-for-python.js --params <params> --secretParams <secretParams> --attestor <attestor>')
		}

		let params: any = {}
		let secretParams: any = {}
		let attestorHostPort = 'localhost:8001'

		// 解析命令行参数
		for (let i = 0; i < args.length; i += 2) {
			const key = args[i]
			const value = args[i + 1]

			switch (key) {
				case '--params':
					params = JSON.parse(value)
					break
				case '--secretParams':
					secretParams = JSON.parse(value)
					break
				case '--attestor':
					if (value === 'local') {
						attestorHostPort = 'localhost:8001'
					} else {
						attestorHostPort = value
					}
					break
			}
		}

		// 验证必需参数
		if (!params.url || !params.method) {
			throw new Error('Missing required params: url and method')
		}

		// 调用 attestor
		const receipt = await createClaimOnAttestor({
			name: 'http',
			params,
			secretParams,
			ownerPrivateKey: process.env.PRIVATE_KEY!,
			client: { url: `ws://${attestorHostPort}/ws` },
			logger
		})

		// 将 receipt 转换为可序列化的 JSON 对象
		const receiptJson = JSON.parse(JSON.stringify(receipt))

		// 构建 JSON 结果
		const jsonResult = JSON.stringify({
			success: true,
			receipt: receiptJson,
			timestamp: Math.floor(Date.now() / 1000)
		})

		// 使用 process.stdout.write 并等待 drain 事件确保完整输出
		await new Promise<void>((resolve, reject) => {
			const success = process.stdout.write(jsonResult)
			if (success) {
				// 写入成功，立即解决
				resolve()
			} else {
				// 缓冲区满，等待 drain 事件
				process.stdout.once('drain', resolve)
				process.stdout.once('error', reject)
			}
		})

		// 清理连接
		const client = getAttestorClientFromPool(`ws://${attestorHostPort}/ws`)
		await client.terminateConnection()

		// 成功退出
		process.exit(0)

	} catch (error) {
		// 构建错误 JSON
		const errorJson = JSON.stringify({
			success: false,
			error: error.message,
			stack: error.stack,
			timestamp: Math.floor(Date.now() / 1000)
		})

		// 使用 process.stdout.write 并等待完成
		await new Promise<void>((resolve, reject) => {
			const success = process.stdout.write(errorJson)
			if (success) {
				resolve()
			} else {
				process.stdout.once('drain', resolve)
				process.stdout.once('error', reject)
			}
		})

		process.exit(1)
	}
}

main()
