#!/usr/bin/env python3
"""
URL匹配模块
实现URL相似度匹配算法，支持多种匹配策略
"""

import re
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse, parse_qs
from difflib import SequenceMatcher


class URLMatcher:
    """URL匹配器，支持多种匹配策略"""

    def __init__(self):
        self.similarity_threshold = 0.6  # 相似度阈值（调整后适合新的权重分配）
        self.base_url_weight = 0.6      # 基础URL权重
        self.params_weight = 0.4        # 参数权重

    def calculate_string_similarity(self, str1: str, str2: str) -> float:
        """
        计算两个字符串的相似度
        使用SequenceMatcher算法（基于Ratcliff/Obershelp算法）

        Args:
            str1: 字符串1
            str2: 字符串2

        Returns:
            相似度分数 (0.0 - 1.0)
        """
        if not str1 or not str2:
            return 0.0

        # 标准化字符串（转小写，去除多余空格）
        str1_norm = str1.lower().strip()
        str2_norm = str2.lower().strip()

        if str1_norm == str2_norm:
            return 1.0

        # 使用SequenceMatcher计算相似度
        matcher = SequenceMatcher(None, str1_norm, str2_norm)
        return matcher.ratio()

    def calculate_jaccard_similarity(self, str1: str, str2: str) -> float:
        """
        计算Jaccard相似度（基于字符集合）

        Args:
            str1: 字符串1
            str2: 字符串2

        Returns:
            Jaccard相似度分数 (0.0 - 1.0)
        """
        if not str1 or not str2:
            return 0.0

        set1 = set(str1.lower())
        set2 = set(str2.lower())

        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))

        return intersection / union if union > 0 else 0.0

    def calculate_levenshtein_similarity(self, str1: str, str2: str) -> float:
        """
        计算基于编辑距离的相似度

        Args:
            str1: 字符串1
            str2: 字符串2

        Returns:
            相似度分数 (0.0 - 1.0)
        """
        if not str1 or not str2:
            return 0.0

        if str1 == str2:
            return 1.0

        # 计算编辑距离
        len1, len2 = len(str1), len(str2)
        dp = [[0] * (len2 + 1) for _ in range(len1 + 1)]

        for i in range(len1 + 1):
            dp[i][0] = i
        for j in range(len2 + 1):
            dp[0][j] = j

        for i in range(1, len1 + 1):
            for j in range(1, len2 + 1):
                if str1[i-1] == str2[j-1]:
                    dp[i][j] = dp[i-1][j-1]
                else:
                    dp[i][j] = min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]) + 1

        max_len = max(len1, len2)
        return 1.0 - (dp[len1][len2] / max_len) if max_len > 0 else 0.0

    def extract_base_url(self, url: str) -> str:
        """
        提取URL中问号前的部分（基础URL）

        Args:
            url: 完整URL

        Returns:
            基础URL（问号前的部分）
        """
        if '?' in url:
            return url.split('?')[0]
        return url

    def parse_url_components(self, url: str) -> Dict[str, any]:
        """
        解析URL组件

        Args:
            url: 完整URL

        Returns:
            URL组件字典
        """
        parsed = urlparse(url)

        return {
            'scheme': parsed.scheme,
            'netloc': parsed.netloc,
            'path': parsed.path,
            'params': parsed.params,
            'query': parsed.query,
            'fragment': parsed.fragment,
            'base_url': f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
            'query_params': parse_qs(parsed.query) if parsed.query else {}
        }

    def match_base_url_exact(self, url1: str, url2: str) -> bool:
        """
        检查两个URL的基础部分（问号前）是否完全匹配

        Args:
            url1: URL 1
            url2: URL 2

        Returns:
            是否完全匹配
        """
        base1 = self.extract_base_url(url1)
        base2 = self.extract_base_url(url2)
        return base1 == base2

    def calculate_url_similarity(self, url1: str, url2: str) -> Dict[str, float]:
        """
        计算两个URL的综合相似度

        Args:
            url1: URL 1
            url2: URL 2

        Returns:
            相似度结果字典
        """
        # 解析URL组件
        comp1 = self.parse_url_components(url1)
        comp2 = self.parse_url_components(url2)

        # 1. 基础URL相似度（多种算法）
        base_similarity_seq = self.calculate_string_similarity(comp1['base_url'], comp2['base_url'])
        base_similarity_jaccard = self.calculate_jaccard_similarity(comp1['base_url'], comp2['base_url'])
        base_similarity_levenshtein = self.calculate_levenshtein_similarity(comp1['base_url'], comp2['base_url'])

        # 基础URL综合相似度（取平均值）
        base_similarity = (base_similarity_seq + base_similarity_jaccard + base_similarity_levenshtein) / 3

        # 2. 查询参数相似度
        query_similarity = self.calculate_string_similarity(comp1['query'], comp2['query'])

        # 3. 完整URL相似度
        full_similarity_seq = self.calculate_string_similarity(url1, url2)
        full_similarity_jaccard = self.calculate_jaccard_similarity(url1, url2)
        full_similarity_levenshtein = self.calculate_levenshtein_similarity(url1, url2)

        full_similarity = (full_similarity_seq + full_similarity_jaccard + full_similarity_levenshtein) / 3

        # 4. 基础URL完全匹配检查
        base_exact_match = self.match_base_url_exact(url1, url2)

        # 5. 综合评分 - 🎯 修复：降低基础URL权重，提高查询参数权重
        if base_exact_match:
            # 如果基础URL完全匹配，仍需要重视查询参数的相似度
            # 对于API URL，查询参数往往比基础URL更重要
            composite_score = 0.3 + (query_similarity * 0.7)
        else:
            # 否则使用加权平均
            composite_score = (base_similarity * self.base_url_weight +
                             query_similarity * self.params_weight)

        return {
            'base_similarity': base_similarity,
            'query_similarity': query_similarity,
            'full_similarity': full_similarity,
            'base_exact_match': base_exact_match,
            'composite_score': composite_score,
            'is_match': composite_score >= self.similarity_threshold,
            'details': {
                'base_similarity_seq': base_similarity_seq,
                'base_similarity_jaccard': base_similarity_jaccard,
                'base_similarity_levenshtein': base_similarity_levenshtein,
                'full_similarity_seq': full_similarity_seq,
                'full_similarity_jaccard': full_similarity_jaccard,
                'full_similarity_levenshtein': full_similarity_levenshtein
            }
        }

    def find_best_match(self, target_url: str, candidate_urls: List[str]) -> Optional[Tuple[str, Dict[str, float]]]:
        """
        在候选URL列表中找到最佳匹配

        Args:
            target_url: 目标URL
            candidate_urls: 候选URL列表

        Returns:
            最佳匹配的URL和相似度结果，如果没有匹配返回None
        """
        best_match = None
        best_score = 0.0
        best_result = None

        for candidate_url in candidate_urls:
            result = self.calculate_url_similarity(target_url, candidate_url)

            if result['composite_score'] > best_score:
                best_score = result['composite_score']
                best_match = candidate_url
                best_result = result

        # 只返回超过阈值的匹配
        if best_score >= self.similarity_threshold:
            return best_match, best_result

        return None

    def set_similarity_threshold(self, threshold: float):
        """设置相似度阈值"""
        self.similarity_threshold = max(0.0, min(1.0, threshold))

    def set_weights(self, base_url_weight: float, params_weight: float):
        """设置权重"""
        total = base_url_weight + params_weight
        if total > 0:
            self.base_url_weight = base_url_weight / total
            self.params_weight = params_weight / total


if __name__ == "__main__":
    # 测试代码
    matcher = URLMatcher()

    # 测试URL
    url1 = "https://www.cmbwinglungbank.com/ibanking/McpCSReqServlet?dse_operationName=NbMsgMsgboxDspProc&dse_processorState=initial&dse_nextEventName=initial.logon&dse_sessionId=AAARCXAYDPFGIYHQBQAJCIBUHGDGIJHZABFNAQHD&mcp_language=cn&dse_pageId=1&dse_parentContextName="
    url2 = "https://www.cmbwinglungbank.com/ibanking/McpCSReqServlet?dse_operationName=NbMsgMsgboxDspProc&dse_processorState=initial&dse_nextEventName=initial.logon&dse_sessionId=DIFFERENT_SESSION_ID&mcp_language=cn&dse_pageId=1&dse_parentContextName="
    url3 = "https://www.cmbwinglungbank.com/ibanking/McpCSReqServlet?jspName=/accountmanagement/NbBkgWel.jsp&dse_sessionId=ANOTHER_SESSION&mcp_funcId=Acm&mcp_language=cn"
    url4 = "https://example.com/api/different"

    print("🧪 URL匹配测试")
    print("=" * 50)

    # 测试1: 相同基础URL，不同参数
    result = matcher.calculate_url_similarity(url1, url2)
    print(f"测试1 - 相同基础URL，不同参数:")
    print(f"  基础URL匹配: {result['base_exact_match']}")
    print(f"  综合评分: {result['composite_score']:.3f}")
    print(f"  是否匹配: {result['is_match']}")
    print()

    # 测试2: 相同基础URL，完全不同参数
    result = matcher.calculate_url_similarity(url1, url3)
    print(f"测试2 - 相同基础URL，完全不同参数:")
    print(f"  基础URL匹配: {result['base_exact_match']}")
    print(f"  综合评分: {result['composite_score']:.3f}")
    print(f"  是否匹配: {result['is_match']}")
    print()

    # 测试3: 完全不同URL
    result = matcher.calculate_url_similarity(url1, url4)
    print(f"测试3 - 完全不同URL:")
    print(f"  基础URL匹配: {result['base_exact_match']}")
    print(f"  综合评分: {result['composite_score']:.3f}")
    print(f"  是否匹配: {result['is_match']}")
    print()

    # 测试4: 最佳匹配查找
    candidates = [url2, url3, url4]
    best_match = matcher.find_best_match(url1, candidates)
    if best_match:
        print(f"最佳匹配: {best_match[0]}")
        print(f"匹配评分: {best_match[1]['composite_score']:.3f}")
    else:
        print("未找到匹配的URL")
