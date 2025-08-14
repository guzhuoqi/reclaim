#!/usr/bin/env node
/**
 * 智能ZK文件下载脚本
 * 优化：如果文件已存在且完整，跳过删除和重新下载步骤
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// ZK文件路径配置
const ZK_BASE_PATH = 'node_modules/@reclaimprotocol/zk-symmetric-crypto';
const RESOURCES_PATH = path.join(ZK_BASE_PATH, 'resources');
const BIN_PATH = path.join(ZK_BASE_PATH, 'bin');

// 关键文件列表 - 用于验证下载完整性
const CRITICAL_FILES = [
    'resources/snarkjs/aes-256-ctr/circuit.wasm',
    'resources/snarkjs/aes-128-ctr/circuit.wasm',
    'resources/snarkjs/chacha20/circuit.wasm',
    'resources/snarkjs/aes-256-ctr/circuit.zkey',
    'resources/snarkjs/aes-128-ctr/circuit.zkey',
    'resources/snarkjs/chacha20/circuit.zkey'
];

/**
 * 检查文件是否存在且大小合理
 */
function checkFileExists(filePath) {
    try {
        const fullPath = path.join(ZK_BASE_PATH, filePath);
        const stats = fs.statSync(fullPath);
        // 检查文件大小是否合理（至少1KB）
        return stats.isFile() && stats.size > 1024;
    } catch (error) {
        return false;
    }
}

/**
 * 检查所有关键文件是否存在
 */
function checkAllFilesExist() {
    console.log('🔍 检查ZK文件完整性...');

    let existingFiles = 0;
    let totalSize = 0;

    for (const file of CRITICAL_FILES) {
        if (checkFileExists(file)) {
            existingFiles++;
            try {
                const fullPath = path.join(ZK_BASE_PATH, file);
                const stats = fs.statSync(fullPath);
                totalSize += stats.size;
                console.log(`  ✅ ${file} (${(stats.size / 1024 / 1024).toFixed(2)} MB)`);
            } catch (error) {
                console.log(`  ❌ ${file} (读取失败)`);
            }
        } else {
            console.log(`  ❌ ${file} (不存在或过小)`);
        }
    }

    console.log(`📊 文件状态: ${existingFiles}/${CRITICAL_FILES.length} 个关键文件存在`);
    console.log(`📦 总大小: ${(totalSize / 1024 / 1024).toFixed(2)} MB`);

    return existingFiles === CRITICAL_FILES.length;
}

/**
 * 获取现有文件数量
 */
function getExistingFileCount() {
    try {
        if (!fs.existsSync(RESOURCES_PATH)) {
            return 0;
        }

        let count = 0;
        function countFiles(dir) {
            const items = fs.readdirSync(dir);
            for (const item of items) {
                const fullPath = path.join(dir, item);
                const stats = fs.statSync(fullPath);
                if (stats.isDirectory()) {
                    countFiles(fullPath);
                } else {
                    count++;
                }
            }
        }

        countFiles(RESOURCES_PATH);
        return count;
    } catch (error) {
        return 0;
    }
}

/**
 * 执行原始下载脚本
 */
function runOriginalDownload() {
    console.log('📥 执行原始下载脚本...');
    try {
        // 执行原始的下载脚本
        execSync('node node_modules/@reclaimprotocol/zk-symmetric-crypto/lib/scripts/download-files', {
            stdio: 'inherit',
            cwd: process.cwd()
        });
        console.log('✅ 下载完成');
        return true;
    } catch (error) {
        console.error('❌ 下载失败:', error.message);
        return false;
    }
}

/**
 * 主函数
 */
function main() {
    console.log('🚀 智能ZK文件下载器启动');
    console.log('='.repeat(50));

    // 检查当前文件状态
    const existingCount = getExistingFileCount();
    console.log(`📁 当前文件数量: ${existingCount}`);

    // 检查关键文件是否完整
    const allFilesExist = checkAllFilesExist();

    if (allFilesExist && existingCount > 50) {
        console.log('');
        console.log('🎉 所有关键ZK文件已存在且完整！');
        console.log('⚡ 跳过下载以节省构建时间');
        console.log('💡 如需强制重新下载，请先删除 resources 目录');
        console.log('');
        console.log('📊 最终统计:');
        console.log(`   文件数量: ${existingCount}`);
        console.log(`   关键文件: ${CRITICAL_FILES.length}/${CRITICAL_FILES.length} 完整`);
        console.log('✅ 智能下载完成 - 无需重新下载');
        return;
    }

    // 如果文件数量较多但不完整，也考虑跳过（可能是部分损坏）
    if (existingCount > 30) {
        console.log('');
        console.log('⚠️ 发现较多现有文件但不完整，为避免不必要的重新下载，跳过处理');
        console.log('💡 如确需重新下载，请手动删除 resources 目录后重试');
        console.log('');
        console.log('📊 当前状态:');
        console.log(`   文件数量: ${existingCount}`);
        console.log(`   关键文件: ${CRITICAL_FILES.filter(f => checkFileExists(f)).length}/${CRITICAL_FILES.length} 存在`);
        console.log('⚡ 跳过下载以节省时间');
        return;
    }

    console.log('');
    if (existingCount > 0) {
        console.log('⚠️  文件不完整或缺失关键文件，需要重新下载');
    } else {
        console.log('📥 未找到ZK文件，开始首次下载');
    }

    // 执行下载
    const success = runOriginalDownload();

    if (success) {
        // 验证下载结果
        console.log('');
        console.log('🔍 验证下载结果...');
        const finalCount = getExistingFileCount();
        const finalCheck = checkAllFilesExist();

        console.log(`📊 最终文件数量: ${finalCount}`);

        if (finalCheck) {
            console.log('✅ 所有关键文件下载成功！');
        } else {
            console.log('⚠️  部分关键文件可能缺失，但下载过程已完成');
        }
    } else {
        console.log('❌ 下载过程失败');
        process.exit(1);
    }
}

// 运行主函数
if (require.main === module) {
    main();
}

module.exports = {
    checkAllFilesExist,
    getExistingFileCount,
    runOriginalDownload
};
