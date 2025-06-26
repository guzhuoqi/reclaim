import { HardhatRuntimeEnvironment } from 'hardhat/types'

const getAttestor = async (host: string, hre: HardhatRuntimeEnvironment) => {
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
    const result = await contract.getAttestor(host)

    console.log('\n=== 节点信息查询 ===')
    console.log(`节点Key: ${host}`)

    if (result === '0x0000000000000000000000000000000000000000') {
      console.log('状态: 未找到该节点')
    } else {
      console.log(`节点地址: ${result}`)

      // 获取节点的质押信息
      try {
        const stakedAmount = await contract.stakedAmounts(result)
        console.log(`质押金额: ${hre.ethers.formatEther(stakedAmount)} ETH`)
      } catch (e) {
        console.log(`质押金额: 获取失败`)
      }

      // 获取待领取奖励
      try {
        const pendingRewards = await contract.pendingRewards(result)
        console.log(`待领取奖励: ${hre.ethers.formatEther(pendingRewards)} ETH`)
      } catch (e) {
        console.log(`待领取奖励: 获取失败`)
      }
    }

    console.log('=== 查询完成 ===\n')
  } catch (error) {
    console.error('调用合约时发生错误:', error)
  }
}
export default getAttestor
