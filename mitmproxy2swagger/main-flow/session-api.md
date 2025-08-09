
新增一个api，主要实现：
给task_session库新增一条记录，
参考这个eg：
    "c4c52433-020a-4d31-99aa-ffb73473c43e": {
      "id": "c4c52433-020a-4d31-99aa-ffb73473c43e",
      "taskId": "", --空串即可
      "providerId": "7b18b8aa-96fa-45e2-8ddd-3697e2a218a2",
      "status": "Pending",
      "completed_at": 1754631361.570976
    }

    其中，需要api传递的入参至少有：providerId；
其他字段，我们来生成即可。

继续新增第二个api，主要实现：
通过session_id来查询，索引到task_session库里的记录，
再通过taskId索引到attestor_db里的responses，
可以把"claim"拎出来放到最前边，一个response记录返回。


      "matched_url": "https://its.bochk.com/acc.overview.do",
      "similarity_score": 0.95,
      "processed_by": "session_based_matcher",
      "attestor_result": {
        "success": false,
        "error": "Process failed with code 1",
        "stderr": "",
        "stdout": "{\"success\":false,\"error\":\"Invalid receipt. Response does not contain \\\"\\\"currency\\\"\\\"\",\"stack\":\"Error: Invalid receipt. Response does not contain \\\"\\\"currency\\\"\\\"\\n    at Object.assertValidProviderReceipt (/Users/gu/IdeaProjects/reclaim/attestor-core/lib/providers/http/index.js:416:31)\\n    at addServerSideReveals (/Users/gu/IdeaProjects/reclaim/attestor-core/lib/client/create-claim.js:365:24)\\n    at async generateTranscript (/Users/gu/IdeaProjects/reclaim/attestor-core/lib/client/create-claim.js:280:9)\\n    at async _createClaimOnAttestor (/Users/gu/IdeaProjects/reclaim/attestor-core/lib/client/create-claim.js:176:24)\\n    at async executeWithRetries (/Users/gu/IdeaProjects/reclaim/attestor-core/lib/utils/retries.js:12:28)\\n    at async main (/Users/gu/IdeaProjects/reclaim/attestor-core/lib/scripts/generate-receipt-for-python.js:68:25)\",\"timestamp\":1754690312}",
        "task_id": "task_2_1754690311",