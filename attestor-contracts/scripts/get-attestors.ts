import { HardhatRuntimeEnvironment } from 'hardhat/types'

const getAttestors = async (hre: HardhatRuntimeEnvironment) => {
  const addresses = require('./addresses.json')
  const governanceAddress = addresses.governance

  const fs = require('fs')
  const ContractArtifact = JSON.parse(
    fs.readFileSync(
      'artifacts/contracts/Governance.sol/Governance.json',
      'utf8'
    )
  )

  const contract = await hre.ethers.getContractAt(
    ContractArtifact.abi,
    governanceAddress
  )

  try {
    //@ts-ignore
    const result = await contract.getAttestors()
    const [keys, addresses] = result

    console.log('\n=== 已注册的节点列表 ===')
    console.log(`总共找到 ${keys.length} 个已注册的节点:\n`)

    if (keys.length === 0) {
      console.log('暂无已注册的节点')
    } else {
      for (let i = 0; i < keys.length; i++) {
        console.log(`节点 ${i + 1}:`)
        console.log(`  Key: ${keys[i]}`)
        console.log(`  Address: ${addresses[i]}`)

        // 获取节点的质押信息
        try {
          const stakedAmount = await contract.stakedAmounts(addresses[i])
          console.log(`  质押金额: ${hre.ethers.formatEther(stakedAmount)} ETH`)
        } catch (e) {
          console.log(`  质押金额: 获取失败`)
        }
        console.log('')
      }
    }

    console.log('=== 查询完成 ===\n')
  } catch (error) {
    console.error('调用合约时发生错误:', error)
  }
}
export default getAttestors
