
mitmproxy2swagger/mitmproxy2swagger：通用的分析工具

如果这个跑不到余额数据，需要定制分析脚本，如下：
银行api增强版脚本：mitmproxy2swagger/enhanced_mitmproxy2swagger

下一步是重放请求：
mitmproxy2swagger/repeat_request_bank

最后一步委托attestor node跑api请求：
依赖上一步的结果：
mitmproxy2swagger/repeat_request_bank/boc_mitm_analysis_1754039887.json
mitmproxy2swagger/repeat_request_bank/boc_request_details_1754039887.json

有这个结果数据，委托：attestor-core
attestor-core/cmb-wing-lung-enhanced.json

attestor-core里边有个命令，读取上边json作为参数，去调provider api获取银行余额数据。