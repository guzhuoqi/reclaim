
---
在[data](../mitmproxy_addons/data)维护一个新DB，维护一个task session记录；
session记录文件也是按日期分割、通过id索引；
session记录有字段--id：唯一id；
session记录有字段--taskId：并且这个id也能索引到[attestor_db](../mitmproxy_addons/data/attestor_db)里的应答信息。
session记录有字段--providerId；
session记录有字段--记录状态：如果能索引到[attestor_db](../mitmproxy_addons/data/attestor_db)里的应答信息，状态是Finished；如果不能索引到，状态是Pending。

实现第一个功能点：
改造[mitmproxy_addons](../mitmproxy_addons)的匹配api的逻辑：
查session记录列表、状态是Pending的，遍历列表，
通过记录中的providerId到[data](data)中的reclaim_providers_*检索，匹配url，
参考：              "url": "https://www.cmbwinglungbank.com/ibanking/McpCSReqServlet?dse_operationName=NbMsgMsgboxDspProc&dse_processorState=initial&dse_nextEventName=initial.logon&dse_sessionId=AAARCXAYDPFGIYHQBQAJCIBUHGDGIJHZABFNAQHD&mcp_language=cn&dse_pageId=1&dse_parentContextName=",
匹配规则分两部分：
1、你结合互联网，看看有没有两个字符串的相似度算法，按照评分来匹配
2、第一个?前的部分完全匹配

匹配成功的，就走attestor node的调用。


---

          "providerConfig": {
            "loginUrl": "https://www.cmbwinglungbank.com/ibanking/logon/NbHomLogonInp.jsp?mcp_language=sc",
            "customInjection": null,
            "userAgent": {
              "ios": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
              "android": null
            },
            "geoLocation": "US",
            "injectionType": "NONE",
            "disableRequestReplay": true,
            "verificationType": "WITNESS",
            "requestData": [
              {
                "url": "https://www.cmbwinglungbank.com/ibanking/McpCSReqServlet?dse_operationName=NbBkgActdetCoaProc2022&dse_processorState=initial&dse_nextEventName=start&dse_sessionId=FGJLGDJSHYJQGBCJDGJNEIHNJNGREHBVFGBLCEGK&mcp_language=sc&dse_pageId=1&dse_parentContextName=&mcp_timestamp=1754566085034&AcctTypeIds=DDA,CUR,SAV,FDA,CON,MEC&AcctTypeId=CON&RequestType=D&selectedProductKey=CON",
                "expectedPageUrl": "",
                "urlType": "CONSTANT",
                "method": "POST",
                "responseMatches": [
                  {
                    "value": "account",
                    "type": "contains",
                    "invert": false,
                    "description": "验证响应包含账户信息",
                    "order": 1,
                    "isOptional": true
                  },
                  {
                    "value": "account",
                    "type": "contains",
                    "invert": false,
                    "description": "验证响应包含账户信息",
                    "order": 2,
                    "isOptional": true
                  }
                ],
                "responseRedactions": [],
                "bodySniff": {
                  "enabled": false,
                  "template": ""
                },
                "requestHash": "0xc7f33c85e2b07397860c7b32e3aefacd609faca952f772098127b7f807df03de",
                "responseVariables": []
              }
            ]
分析一下这个provider：为啥responseMatches没有正则？

responseMatches、responseRedactions两个都得填充一下；
因为是数组，除了能匹配账号，还有余额、资产、名称等用户信息，如果一个应答报文中能匹配到多个，就有多个正则，然后放到数组中；
并不是匹配到一种，就break了；

同样的规则被生成了两次（order 1和2），这表明可能有重复的模式匹配----这个也修复一下。


注意：
1、responseMatches数组，一定是能匹配成功，才能纳入
2、responseRedactions数组，是要能提取出用户的金融信息

务必要按这个来实现



              "url": "https://www.cmbwinglungbank.com/ibanking/McpCSReqServlet?dse_operationName=NbBkgActdetCoaProc2022&dse_processorState=initial&dse_nextEventName=start&dse_sessionId=FGJLGDJSHYJQGBCJDGJNEIHNJNGREHBVFGBLCEGK&mcp_language=sc&dse_pageId=1&dse_parentContextName=&mcp_timestamp=1754566085034&AcctTypeIds=DDA,CUR,SAV,FDA,CON,MEC&AcctTypeId=CON&RequestType=D&selectedProductKey=CON",
就拿这个url对应的应答报文来分析，哪里可能匹配到那么多responseMatches；一定要真实匹配到应答内容，才能加入到数组。


    "c4c52433-020a-4d31-99aa-ffb73473c43e": {
接下来，我们为这个provider，构造一个进行中的session记录，为我的下一步跑银行类请求做准备；

[task_sessions](../mitmproxy_addons/data/task_sessions)