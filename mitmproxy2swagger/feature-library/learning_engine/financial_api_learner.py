#!/usr/bin/env python3
"""
金融API增强学习引擎
Financial API Enhanced Learning Engine

基于现有特征库，通过模式匹配和邻居分析，学习新的金融API特征
并动态更新特征库，提高API识别的准确性和覆盖率。

核心功能：
1. 宽松前置扫描 - 降低阈值，收集更多候选API
2. 邻居报文分析 - 基于时间序列和调用链分析API关系
3. 模式学习 - 从成功案例中提取新的URL和响应模式
4. 特征库更新 - 将学习到的新知识补充到特征库
5. 确定性增强 - 通过多维度验证提高学习的可靠性
"""

import json
import re
import sys
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from urllib.parse import urlparse, parse_qs
import difflib

# 添加路径以导入现有模块
sys.path.append('mitmproxy2swagger/mitmproxy2swagger')
sys.path.append('mitmproxy2swagger/feature-library/ai_analysis_features')

from financial_api_analyzer import FinancialAPIAnalyzer


@dataclass
class APICandidate:
    """API候选对象"""
    url: str
    method: str
    status_code: int
    response_content: str
    request_body: str
    timestamp: datetime
    domain: str
    confidence_score: float = 0.0
    learned_patterns: List[str] = None
    neighbor_context: Dict[str, Any] = None

    def __post_init__(self):
        if self.learned_patterns is None:
            self.learned_patterns = []
        if self.neighbor_context is None:
            self.neighbor_context = {}


@dataclass
class LearnedPattern:
    """学习到的模式"""
    pattern_type: str  # url_pattern, response_pattern, sequence_pattern
    pattern_value: str
    confidence: float
    source_apis: List[str]
    validation_count: int = 0
    institution: str = ""
    category: str = ""


class FinancialAPILearner:
    """金融API增强学习引擎"""

    def __init__(self, feature_library_path: str = None):
        """初始化学习引擎"""
        self.logger = logging.getLogger(__name__)

        # 加载现有特征库
        if feature_library_path is None:
            feature_library_path = 'mitmproxy2swagger/feature-library/ai_analysis_features/financial_api_features.json'

        self.feature_library_path = feature_library_path
        self.feature_library = self._load_feature_library()

        # 初始化分析器
        self.analyzer = FinancialAPIAnalyzer()

        # 学习配置 - 优化后的参数
        self.config = {
            'loose_scan_threshold': 0.05,  # 降低宽松扫描阈值 (0.1 -> 0.05)
            'modern_api_bonus': 0.15,       # 现代API额外加分
            'json_response_bonus': 0.1,     # JSON响应额外加分
            'large_response_bonus': 0.05,   # 大响应额外加分
            'neighbor_time_window': 300,    # 邻居分析时间窗口(秒)
            'min_confidence_for_learning': 0.4,  # 降低学习的最小置信度 (0.6 -> 0.4)
            'pattern_validation_threshold': 2,   # 模式验证阈值
            'max_candidates_per_domain': 100,   # 增加每个域名最大候选数 (50 -> 100)
            'enable_modern_api_detection': True  # 启用现代API检测
        }

        # 学习状态
        self.learned_patterns: List[LearnedPattern] = []
        self.api_candidates: List[APICandidate] = []
        self.learning_stats = {
            'total_scanned': 0,
            'candidates_found': 0,
            'patterns_learned': 0,
            'feature_library_updates': 0
        }

    def _load_feature_library(self) -> Dict[str, Any]:
        """加载特征库"""
        try:
            with open(self.feature_library_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"加载特征库失败: {e}")
            return {}

    def _save_feature_library(self):
        """保存特征库"""
        try:
            # 备份原文件
            backup_path = f"{self.feature_library_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            with open(self.feature_library_path, 'r', encoding='utf-8') as f:
                backup_content = f.read()
            with open(backup_path, 'w', encoding='utf-8') as f:
                f.write(backup_content)

            # 保存更新后的特征库
            with open(self.feature_library_path, 'w', encoding='utf-8') as f:
                json.dump(self.feature_library, f, indent=2, ensure_ascii=False)

            self.logger.info(f"特征库已更新，备份保存至: {backup_path}")
            return True
        except Exception as e:
            self.logger.error(f"保存特征库失败: {e}")
            return False

    def loose_scan_apis(self, flows: List[Dict[str, Any]]) -> List[APICandidate]:
        """宽松前置扫描 - 收集所有可能的金融API候选"""
        candidates = []

        for flow in flows:
            try:
                url = flow.get('url', '')
                method = flow.get('method', '').upper()
                status_code = flow.get('status_code', 0)
                response_body = flow.get('response_body', '')
                request_body = flow.get('request_body', '')

                # 基本过滤
                if not url or status_code != 200:
                    continue

                # 解析域名
                parsed_url = urlparse(url)
                domain = parsed_url.netloc.lower()

                # 跳过明显的静态资源
                if self._is_static_resource(url):
                    continue

                # 宽松的金融机构识别
                if self._is_potential_financial_domain(domain):
                    # 宽松的API模式匹配
                    confidence = self._calculate_loose_confidence(url, response_body, domain)

                    if confidence >= self.config['loose_scan_threshold']:
                        candidate = APICandidate(
                            url=url,
                            method=method,
                            status_code=status_code,
                            response_content=response_body,
                            request_body=request_body,
                            timestamp=datetime.now(),  # 实际应该从flow中获取
                            domain=domain,
                            confidence_score=confidence
                        )
                        candidates.append(candidate)

                self.learning_stats['total_scanned'] += 1

            except Exception as e:
                self.logger.warning(f"处理flow时出错: {e}")
                continue

        # 按域名限制候选数量
        candidates = self._limit_candidates_per_domain(candidates)

        # 保存候选API到实例变量
        self.api_candidates = candidates

        self.learning_stats['candidates_found'] = len(candidates)
        self.logger.info(f"宽松扫描完成，发现 {len(candidates)} 个候选API")

        return candidates

    def _is_static_resource(self, url: str) -> bool:
        """判断是否为静态资源"""
        static_extensions = ['.js', '.css', '.png', '.jpg', '.gif', '.ico', '.woff', '.ttf', '.svg']
        static_keywords = ['google', 'doubleclick', 'analytics', 'facebook', 'twitter']

        url_lower = url.lower()

        # 检查文件扩展名
        if any(url_lower.endswith(ext) for ext in static_extensions):
            return True

        # 检查第三方服务
        if any(keyword in url_lower for keyword in static_keywords):
            return True

        return False

    def _is_potential_financial_domain(self, domain: str) -> bool:
        """宽松的金融机构域名识别"""
        # 已知金融机构域名
        known_financial_domains = set()
        for category in self.feature_library.values():
            if isinstance(category, dict) and 'institutions' in category:
                for inst_data in category['institutions'].values():
                    if 'domains' in inst_data:
                        known_financial_domains.update(inst_data['domains'])

        if domain in known_financial_domains:
            return True

        # 金融关键字匹配 - 增强版
        financial_keywords = [
            # 传统银行
            'bank', 'banking', 'finance', 'investment', 'wealth', 'credit',
            'hsbc', 'citibank', 'jpmorgan', 'goldman', 'morgan', 'wells',
            'boc', 'icbc', 'ccb', 'abc', 'cmb', 'cib', 'spdb', 'citic',
            'hangseng', 'bochk', 'dbs', 'ocbc', 'uob', 'maybank',
            # 中国银行特殊域名
            'mybank', 'epass', 'winglungbank', 'cmbwinglungbank',
            # 现代券商
            'lbkrs', 'longbridge', 'longport', 'futu', 'futuhk', 'futunn',
            'tiger', 'tigerbrokers', 'itiger', 'webull', 'moomoo',
            'securities', 'brokerage', 'trading', 'broker',
            # 支付和金融科技
            'pay', 'payment', 'wallet', 'fintech', 'alipay', 'wechatpay'
        ]

        if any(keyword in domain for keyword in financial_keywords):
            return True

        # 特殊域名模式匹配
        special_patterns = [
            r'.*bank.*\.com',      # 包含bank的域名
            r'.*securities.*\.com', # 包含securities的域名
            r'.*trading.*\.com',   # 包含trading的域名
            r'.*finance.*\.com',   # 包含finance的域名
            r'.*\.com\.cn$',       # 中国域名 (.com.cn)
            r'.*\.com\.hk$'        # 香港域名 (.com.hk)
        ]

        import re
        for pattern in special_patterns:
            if re.match(pattern, domain):
                return True

        return False

    def _calculate_loose_confidence(self, url: str, response_content: str, domain: str) -> float:
        """计算宽松置信度分数 - 增强版"""
        confidence = 0.0

        # URL模式匹配 (权重: 0.3)
        url_score = self._score_url_patterns(url)
        confidence += url_score * 0.3

        # 响应内容匹配 (权重: 0.3)
        content_score = self._score_response_content(response_content)
        confidence += content_score * 0.3

        # 域名匹配 (权重: 0.2)
        domain_score = self._score_domain(domain)
        confidence += domain_score * 0.2

        # 现代API模式加分 (权重: 0.2)
        modern_api_score = self._score_modern_api_patterns(url, response_content, domain)
        confidence += modern_api_score * 0.2

        return min(confidence, 1.0)

    def _score_url_patterns(self, url: str) -> float:
        """URL模式评分"""
        url_lower = url.lower()
        score = 0.0

        # 金融API关键字
        financial_keywords = [
            'account', 'balance', 'transaction', 'transfer', 'payment',
            'portfolio', 'investment', 'wealth', 'asset', 'deposit',
            'loan', 'credit', 'card', 'statement', 'history',
            'dashboard', 'overview', 'summary', 'detail', 'info',
            'api', 'service', 'data', 'query', 'get', 'fetch'
        ]

        for keyword in financial_keywords:
            if keyword in url_lower:
                score += 0.1

        # API路径模式 - 增强版
        api_patterns = ['/api/', '/service/', '/rest/', '/v1/', '/v2/', '/data/']
        for pattern in api_patterns:
            if pattern in url_lower:
                score += 0.2

        # 现代券商API模式
        modern_patterns = ['/api/forward/', '/api/third_party/', '/api/v1/', '/api/v2/']
        for pattern in modern_patterns:
            if pattern in url_lower:
                score += 0.3  # 现代API模式给更高分

        # 传统银行Servlet模式
        servlet_patterns = ['servlet', '.do']
        for pattern in servlet_patterns:
            if pattern in url_lower:
                score += 0.15  # 传统模式给适中分数

        return min(score, 1.0)

    def _score_response_content(self, content: str) -> float:
        """响应内容评分"""
        if not content:
            return 0.0

        content_lower = content.lower()
        score = 0.0

        # JSON格式加分
        if content.strip().startswith('{') or content.strip().startswith('['):
            score += 0.3

        # 金融数据关键字
        financial_data_keywords = [
            'balance', 'amount', 'currency', 'account', 'transaction',
            'portfolio', 'asset', 'investment', 'deposit', 'credit',
            'hkd', 'usd', 'cny', 'eur', 'gbp', 'jpy',
            'total', 'available', 'current', 'saving', 'checking'
        ]

        for keyword in financial_data_keywords:
            if keyword in content_lower:
                score += 0.05

        return min(score, 1.0)

    def _score_domain(self, domain: str) -> float:
        """域名评分"""
        # 检查是否在已知金融机构列表中
        for category in self.feature_library.values():
            if isinstance(category, dict) and 'institutions' in category:
                for inst_data in category['institutions'].values():
                    if 'domains' in inst_data and domain in inst_data['domains']:
                        return 1.0

        # 金融关键字匹配
        financial_keywords = ['bank', 'finance', 'investment', 'wealth']
        for keyword in financial_keywords:
            if keyword in domain:
                return 0.7

        return 0.0

    def _score_modern_api_patterns(self, url: str, response_content: str, domain: str) -> float:
        """现代API模式评分 - 专门针对长桥等现代券商"""
        score = 0.0
        url_lower = url.lower()

        # 现代券商域名识别
        modern_securities_domains = [
            'lbkrs.com', 'longbridge.com', 'futu5.com', 'futuhk.com',
            'tigerbrokers.com', 'itiger.com', 'webull.com', 'moomoo.com'
        ]

        if any(domain_pattern in domain for domain_pattern in modern_securities_domains):
            score += 0.4  # 现代券商域名高分

        # 现代API路径模式
        modern_api_patterns = [
            '/api/forward/',     # 长桥特有模式
            '/api/third_party/', # 第三方认证
            '/api/v1/',          # 版本化API
            '/api/v2/',
            '/portfolio/',       # 投资组合
            '/account/',         # 账户管理
            '/auth/',           # 认证
            '/config/',         # 配置
            '/member/'          # 会员信息
        ]

        for pattern in modern_api_patterns:
            if pattern in url_lower:
                score += 0.2

        # JSON响应格式加分
        if response_content and (response_content.strip().startswith('{') or response_content.strip().startswith('[')):
            score += 0.2

        # 大响应加分 (通常包含更多数据)
        if response_content and len(response_content) > 1000:
            score += 0.1

        # 现代金融术语
        modern_financial_terms = [
            'available_cash', 'max_purchase', 'credit_limit', 'total_asset',
            'account_no', 'account_channel', 'member_info', 'portfolio',
            'position', 'trading', 'execution', 'order_id'
        ]

        if response_content:
            content_lower = response_content.lower()
            for term in modern_financial_terms:
                if term in content_lower:
                    score += 0.05

        return min(score, 1.0)

    def _limit_candidates_per_domain(self, candidates: List[APICandidate]) -> List[APICandidate]:
        """限制每个域名的候选数量"""
        domain_candidates = defaultdict(list)

        for candidate in candidates:
            domain_candidates[candidate.domain].append(candidate)

        limited_candidates = []
        for domain, domain_list in domain_candidates.items():
            # 按置信度排序，取前N个
            sorted_candidates = sorted(domain_list, key=lambda x: x.confidence_score, reverse=True)
            limited_candidates.extend(sorted_candidates[:self.config['max_candidates_per_domain']])

        return limited_candidates

    def analyze_neighbor_context(self, candidates: List[APICandidate], all_flows: List[Dict[str, Any]]) -> List[APICandidate]:
        """邻居报文分析 - 基于时间序列和调用链分析API关系"""
        self.logger.info("开始邻居报文分析...")

        # 为每个候选API分析其邻居上下文
        for candidate in candidates:
            try:
                neighbor_context = self._extract_neighbor_context(candidate, all_flows)
                candidate.neighbor_context = neighbor_context

                # 基于邻居上下文调整置信度
                context_boost = self._calculate_context_boost(neighbor_context)
                candidate.confidence_score = min(candidate.confidence_score + context_boost, 1.0)

            except Exception as e:
                self.logger.warning(f"分析邻居上下文时出错: {e}")
                continue

        return candidates

    def _extract_neighbor_context(self, candidate: APICandidate, all_flows: List[Dict[str, Any]]) -> Dict[str, Any]:
        """提取邻居上下文信息"""
        context = {
            'preceding_apis': [],
            'following_apis': [],
            'same_domain_apis': [],
            'authentication_sequence': [],
            'business_flow_indicators': []
        }

        candidate_time = candidate.timestamp
        time_window = timedelta(seconds=self.config['neighbor_time_window'])

        for flow in all_flows:
            try:
                flow_url = flow.get('url', '')
                flow_domain = urlparse(flow_url).netloc.lower()
                flow_time = datetime.now()  # 实际应该从flow中解析时间戳

                # 同域名API
                if flow_domain == candidate.domain and flow_url != candidate.url:
                    context['same_domain_apis'].append({
                        'url': flow_url,
                        'method': flow.get('method', ''),
                        'status': flow.get('status_code', 0)
                    })

                # 时间窗口内的API
                time_diff = abs((flow_time - candidate_time).total_seconds())
                if time_diff <= self.config['neighbor_time_window']:
                    api_info = {
                        'url': flow_url,
                        'method': flow.get('method', ''),
                        'status': flow.get('status_code', 0),
                        'time_offset': (flow_time - candidate_time).total_seconds()
                    }

                    if flow_time < candidate_time:
                        context['preceding_apis'].append(api_info)
                    elif flow_time > candidate_time:
                        context['following_apis'].append(api_info)

                # 认证序列检测
                if self._is_authentication_api(flow_url):
                    context['authentication_sequence'].append({
                        'url': flow_url,
                        'time_offset': (flow_time - candidate_time).total_seconds()
                    })

            except Exception as e:
                continue

        # 业务流程指标
        context['business_flow_indicators'] = self._detect_business_flow_patterns(context)

        return context

    def _is_authentication_api(self, url: str) -> bool:
        """检测是否为认证API"""
        auth_keywords = ['login', 'auth', 'authenticate', 'signin', 'logon', 'verify', 'token']
        url_lower = url.lower()
        return any(keyword in url_lower for keyword in auth_keywords)

    def _detect_business_flow_patterns(self, context: Dict[str, Any]) -> List[str]:
        """检测业务流程模式"""
        patterns = []

        # 检测登录->业务API模式
        auth_before = any(api['time_offset'] < 0 for api in context['authentication_sequence'])
        if auth_before:
            patterns.append('post_authentication_api')

        # 检测批量API调用模式
        if len(context['same_domain_apis']) > 5:
            patterns.append('batch_api_calls')

        # 检测dashboard加载模式
        dashboard_keywords = ['dashboard', 'overview', 'summary', 'home']
        dashboard_apis = [api for api in context['same_domain_apis']
                         if any(keyword in api['url'].lower() for keyword in dashboard_keywords)]
        if dashboard_apis:
            patterns.append('dashboard_loading_sequence')

        return patterns

    def _calculate_context_boost(self, context: Dict[str, Any]) -> float:
        """基于上下文计算置信度提升"""
        boost = 0.0

        # 认证后API加分
        if 'post_authentication_api' in context['business_flow_indicators']:
            boost += 0.2

        # Dashboard加载序列加分
        if 'dashboard_loading_sequence' in context['business_flow_indicators']:
            boost += 0.15

        # 同域名API数量加分
        same_domain_count = len(context['same_domain_apis'])
        if same_domain_count > 3:
            boost += min(same_domain_count * 0.02, 0.1)

        # 批量调用模式加分
        if 'batch_api_calls' in context['business_flow_indicators']:
            boost += 0.1

        return boost

    def learn_patterns_from_candidates(self, candidates: List[APICandidate]) -> List[LearnedPattern]:
        """从候选API中学习新模式"""
        self.logger.info("开始从候选API学习新模式...")

        learned_patterns = []

        # 按置信度过滤高质量候选
        high_confidence_candidates = [
            c for c in candidates
            if c.confidence_score >= self.config['min_confidence_for_learning']
        ]

        self.logger.info(f"高置信度候选API数量: {len(high_confidence_candidates)}")

        # 学习URL模式
        url_patterns = self._learn_url_patterns(high_confidence_candidates)
        learned_patterns.extend(url_patterns)

        # 学习响应模式
        response_patterns = self._learn_response_patterns(high_confidence_candidates)
        learned_patterns.extend(response_patterns)

        # 学习序列模式
        sequence_patterns = self._learn_sequence_patterns(high_confidence_candidates)
        learned_patterns.extend(sequence_patterns)

        self.learned_patterns.extend(learned_patterns)
        self.learning_stats['patterns_learned'] = len(learned_patterns)

        self.logger.info(f"学习到 {len(learned_patterns)} 个新模式")

        return learned_patterns

    def _learn_url_patterns(self, candidates: List[APICandidate]) -> List[LearnedPattern]:
        """学习URL模式"""
        patterns = []

        # 按域名分组
        domain_groups = defaultdict(list)
        for candidate in candidates:
            domain_groups[candidate.domain].append(candidate)

        for domain, domain_candidates in domain_groups.items():
            if len(domain_candidates) < 2:  # 至少需要2个样本
                continue

            # 提取URL路径模式
            paths = [urlparse(c.url).path for c in domain_candidates]
            common_patterns = self._extract_common_url_patterns(paths)

            for pattern in common_patterns:
                learned_pattern = LearnedPattern(
                    pattern_type='url_pattern',
                    pattern_value=pattern,
                    confidence=0.7,  # 初始置信度
                    source_apis=[c.url for c in domain_candidates],
                    institution=self._identify_institution(domain),
                    category='financial_api'
                )
                patterns.append(learned_pattern)

        return patterns

    def _extract_common_url_patterns(self, paths: List[str]) -> List[str]:
        """提取URL路径的公共模式"""
        patterns = []

        # 简单的公共前缀/后缀检测
        if len(paths) < 2:
            return patterns

        # 查找公共前缀
        common_prefix = self._find_common_prefix(paths)
        if len(common_prefix) > 10:  # 至少10个字符
            patterns.append(f"{common_prefix}*")

        # 查找包含特定关键字的模式
        financial_keywords = ['account', 'balance', 'transaction', 'portfolio', 'dashboard']
        for keyword in financial_keywords:
            matching_paths = [p for p in paths if keyword in p.lower()]
            if len(matching_paths) >= 2:
                patterns.append(f"*{keyword}*")

        return patterns

    def _find_common_prefix(self, strings: List[str]) -> str:
        """查找字符串列表的公共前缀"""
        if not strings:
            return ""

        prefix = strings[0]
        for string in strings[1:]:
            while not string.startswith(prefix):
                prefix = prefix[:-1]
                if not prefix:
                    break

        return prefix

    def _learn_response_patterns(self, candidates: List[APICandidate]) -> List[LearnedPattern]:
        """学习响应内容模式"""
        patterns = []

        # 收集所有JSON响应
        json_responses = []
        for candidate in candidates:
            content = candidate.response_content.strip()
            if content.startswith('{') or content.startswith('['):
                try:
                    json_data = json.loads(content)
                    json_responses.append((candidate, json_data))
                except:
                    continue

        if len(json_responses) < 2:
            return patterns

        # 分析JSON结构模式
        common_keys = self._find_common_json_keys(json_responses)

        for key_pattern in common_keys:
            learned_pattern = LearnedPattern(
                pattern_type='response_pattern',
                pattern_value=key_pattern,
                confidence=0.6,
                source_apis=[c.url for c, _ in json_responses],
                category='json_structure'
            )
            patterns.append(learned_pattern)

        return patterns

    def _find_common_json_keys(self, json_responses: List[Tuple[APICandidate, Any]]) -> List[str]:
        """查找JSON响应的公共键模式"""
        key_patterns = []

        # 收集所有键
        all_keys = set()
        for _, json_data in json_responses:
            if isinstance(json_data, dict):
                all_keys.update(self._extract_json_keys(json_data))

        # 查找在多个响应中出现的键
        key_counts = Counter()
        for _, json_data in json_responses:
            if isinstance(json_data, dict):
                response_keys = set(self._extract_json_keys(json_data))
                for key in response_keys:
                    key_counts[key] += 1

        # 选择出现频率高的键作为模式
        min_occurrences = max(2, len(json_responses) // 2)
        for key, count in key_counts.items():
            if count >= min_occurrences:
                key_patterns.append(key)

        return key_patterns

    def _extract_json_keys(self, json_data: Any, prefix: str = "") -> List[str]:
        """递归提取JSON中的所有键"""
        keys = []

        if isinstance(json_data, dict):
            for key, value in json_data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                keys.append(full_key)

                # 递归处理嵌套对象（限制深度）
                if isinstance(value, (dict, list)) and len(prefix.split('.')) < 3:
                    keys.extend(self._extract_json_keys(value, full_key))

        elif isinstance(json_data, list) and json_data:
            # 处理数组的第一个元素
            keys.extend(self._extract_json_keys(json_data[0], prefix))

        return keys

    def _learn_sequence_patterns(self, candidates: List[APICandidate]) -> List[LearnedPattern]:
        """学习API调用序列模式"""
        patterns = []

        # 按域名分组分析序列
        domain_groups = defaultdict(list)
        for candidate in candidates:
            if candidate.neighbor_context:
                domain_groups[candidate.domain].append(candidate)

        for domain, domain_candidates in domain_groups.items():
            if len(domain_candidates) < 2:
                continue

            # 分析认证后API调用模式
            auth_sequences = self._extract_auth_sequences(domain_candidates)
            for sequence in auth_sequences:
                learned_pattern = LearnedPattern(
                    pattern_type='sequence_pattern',
                    pattern_value=sequence,
                    confidence=0.8,
                    source_apis=[c.url for c in domain_candidates],
                    institution=self._identify_institution(domain),
                    category='authentication_flow'
                )
                patterns.append(learned_pattern)

            # 分析批量API调用模式
            batch_patterns = self._extract_batch_patterns(domain_candidates)
            for pattern in batch_patterns:
                learned_pattern = LearnedPattern(
                    pattern_type='sequence_pattern',
                    pattern_value=pattern,
                    confidence=0.7,
                    source_apis=[c.url for c in domain_candidates],
                    institution=self._identify_institution(domain),
                    category='batch_loading'
                )
                patterns.append(learned_pattern)

        return patterns

    def _extract_auth_sequences(self, candidates: List[APICandidate]) -> List[str]:
        """提取认证序列模式"""
        sequences = []

        # 查找认证后API模式
        post_auth_apis = [
            c for c in candidates
            if 'post_authentication_api' in c.neighbor_context.get('business_flow_indicators', [])
        ]

        if len(post_auth_apis) >= 2:
            sequences.append('auth_login -> business_api_calls')

        return sequences

    def _extract_batch_patterns(self, candidates: List[APICandidate]) -> List[str]:
        """提取批量调用模式"""
        patterns = []

        # 查找dashboard加载模式
        dashboard_apis = [
            c for c in candidates
            if 'dashboard_loading_sequence' in c.neighbor_context.get('business_flow_indicators', [])
        ]

        if len(dashboard_apis) >= 2:
            patterns.append('dashboard_load -> multiple_api_calls')

        return patterns

    def _identify_institution(self, domain: str) -> str:
        """识别金融机构"""
        # 检查已知机构
        for category in self.feature_library.values():
            if isinstance(category, dict) and 'institutions' in category:
                for inst_key, inst_data in category['institutions'].items():
                    if 'domains' in inst_data and domain in inst_data['domains']:
                        return inst_data.get('name', inst_key)

        # 基于域名推断
        if 'hsbc' in domain:
            return 'HSBC'
        elif 'bochk' in domain or 'boc' in domain:
            return '中银香港'
        elif 'hangseng' in domain:
            return '恒生银行'
        elif 'dbs' in domain:
            return 'DBS'
        elif 'citibank' in domain or 'citi' in domain:
            return '花旗银行'

        return 'Unknown'

    def update_feature_library(self, learned_patterns: List[LearnedPattern]) -> bool:
        """更新特征库"""
        self.logger.info("开始更新特征库...")

        if not learned_patterns:
            self.logger.info("没有新模式需要更新")
            return True

        try:
            # 验证模式质量
            validated_patterns = self._validate_patterns(learned_patterns)

            if not validated_patterns:
                self.logger.info("没有通过验证的模式")
                return True

            # 更新特征库结构
            updates_made = 0

            for pattern in validated_patterns:
                if self._add_pattern_to_library(pattern):
                    updates_made += 1

            if updates_made > 0:
                # 保存更新后的特征库
                if self._save_feature_library():
                    self.learning_stats['feature_library_updates'] = updates_made
                    self.logger.info(f"成功更新特征库，添加了 {updates_made} 个新模式")
                    return True
                else:
                    self.logger.error("保存特征库失败")
                    return False
            else:
                self.logger.info("没有新模式被添加到特征库")
                return True

        except Exception as e:
            self.logger.error(f"更新特征库时出错: {e}")
            return False

    def _validate_patterns(self, patterns: List[LearnedPattern]) -> List[LearnedPattern]:
        """验证模式质量"""
        validated = []

        for pattern in patterns:
            # 基本质量检查
            if pattern.confidence < 0.5:
                continue

            if len(pattern.source_apis) < 2:
                continue

            # 检查是否已存在类似模式
            if self._is_duplicate_pattern(pattern):
                continue

            validated.append(pattern)

        return validated

    def _is_duplicate_pattern(self, pattern: LearnedPattern) -> bool:
        """检查是否为重复模式"""
        # 简单的重复检查
        for existing_pattern in self.learned_patterns:
            if (existing_pattern.pattern_type == pattern.pattern_type and
                existing_pattern.pattern_value == pattern.pattern_value):
                return True

        return False

    def _add_pattern_to_library(self, pattern: LearnedPattern) -> bool:
        """将模式添加到特征库"""
        try:
            institution = pattern.institution
            if not institution or institution == 'Unknown':
                return False

            # 查找或创建机构条目
            institution_key = self._find_or_create_institution_key(institution)
            if not institution_key:
                return False

            # 根据模式类型添加到相应位置
            if pattern.pattern_type == 'url_pattern':
                self._add_url_pattern(institution_key, pattern)
            elif pattern.pattern_type == 'response_pattern':
                self._add_response_pattern(institution_key, pattern)
            elif pattern.pattern_type == 'sequence_pattern':
                self._add_sequence_pattern(institution_key, pattern)

            return True

        except Exception as e:
            self.logger.warning(f"添加模式到特征库失败: {e}")
            return False

    def _find_or_create_institution_key(self, institution: str) -> Optional[str]:
        """查找或创建机构键"""
        # 查找现有机构
        for category_key, category in self.feature_library.items():
            if isinstance(category, dict) and 'institutions' in category:
                for inst_key, inst_data in category['institutions'].items():
                    if inst_data.get('name') == institution:
                        return f"{category_key}.institutions.{inst_key}"

        # 创建新机构条目（简化版本，实际可能需要更复杂的逻辑）
        if 'learned_institutions' not in self.feature_library:
            self.feature_library['learned_institutions'] = {
                'description': '学习到的新金融机构',
                'institutions': {}
            }

        # 生成新的机构键
        inst_key = institution.lower().replace(' ', '_').replace('银行', '_bank')
        self.feature_library['learned_institutions']['institutions'][inst_key] = {
            'name': institution,
            'domains': [],
            'api_patterns': {},
            'value_indicators': {
                'high_value_keywords': [],
                'response_patterns': [],
                'bonus_weight': 10
            },
            'learned_date': datetime.now().isoformat()
        }

        return f"learned_institutions.institutions.{inst_key}"

    def _add_url_pattern(self, institution_key: str, pattern: LearnedPattern):
        """添加URL模式"""
        keys = institution_key.split('.')
        inst_data = self.feature_library
        for key in keys:
            inst_data = inst_data[key]

        if 'api_patterns' not in inst_data:
            inst_data['api_patterns'] = {}

        if 'learned_patterns' not in inst_data['api_patterns']:
            inst_data['api_patterns']['learned_patterns'] = []

        inst_data['api_patterns']['learned_patterns'].append(pattern.pattern_value)

    def _add_response_pattern(self, institution_key: str, pattern: LearnedPattern):
        """添加响应模式"""
        keys = institution_key.split('.')
        inst_data = self.feature_library
        for key in keys:
            inst_data = inst_data[key]

        if 'value_indicators' not in inst_data:
            inst_data['value_indicators'] = {'response_patterns': []}

        if 'response_patterns' not in inst_data['value_indicators']:
            inst_data['value_indicators']['response_patterns'] = []

        inst_data['value_indicators']['response_patterns'].append(pattern.pattern_value)

    def _add_sequence_pattern(self, institution_key: str, pattern: LearnedPattern):
        """添加序列模式"""
        keys = institution_key.split('.')
        inst_data = self.feature_library
        for key in keys:
            inst_data = inst_data[key]

        if 'sequence_patterns' not in inst_data:
            inst_data['sequence_patterns'] = []

        inst_data['sequence_patterns'].append({
            'pattern': pattern.pattern_value,
            'confidence': pattern.confidence,
            'category': pattern.category
        })

    def learn_from_flows(self, flows: List[Dict[str, Any]]) -> Dict[str, Any]:
        """主要学习流程 - 从流数据中学习新的金融API模式"""
        self.logger.info("开始金融API增强学习流程...")

        try:
            # 第一阶段：宽松前置扫描
            self.logger.info("第一阶段：宽松前置扫描")
            candidates = self.loose_scan_apis(flows)

            if not candidates:
                self.logger.info("没有发现候选API")
                return self._generate_learning_report()

            # 第二阶段：邻居报文分析
            self.logger.info("第二阶段：邻居报文分析")
            enriched_candidates = self.analyze_neighbor_context(candidates, flows)

            # 第三阶段：模式学习
            self.logger.info("第三阶段：模式学习")
            learned_patterns = self.learn_patterns_from_candidates(enriched_candidates)

            # 第四阶段：特征库更新
            self.logger.info("第四阶段：特征库更新")
            update_success = self.update_feature_library(learned_patterns)

            # 生成学习报告
            report = self._generate_learning_report()
            report['update_success'] = update_success
            report['learned_patterns'] = [asdict(p) for p in learned_patterns]
            report['high_confidence_candidates'] = [
                asdict(c) for c in enriched_candidates
                if c.confidence_score >= self.config['min_confidence_for_learning']
            ]

            self.logger.info("金融API增强学习流程完成")
            return report

        except Exception as e:
            self.logger.error(f"学习流程出错: {e}")
            return {
                'success': False,
                'error': str(e),
                'stats': self.learning_stats
            }

    def _generate_learning_report(self) -> Dict[str, Any]:
        """生成学习报告"""
        return {
            'success': True,
            'timestamp': datetime.now().isoformat(),
            'stats': self.learning_stats.copy(),
            'config': self.config.copy(),
            'summary': {
                'total_scanned': self.learning_stats['total_scanned'],
                'candidates_found': self.learning_stats['candidates_found'],
                'patterns_learned': self.learning_stats['patterns_learned'],
                'feature_library_updates': self.learning_stats['feature_library_updates']
            }
        }

    def export_learned_knowledge(self, output_path: str) -> bool:
        """导出学习到的知识"""
        try:
            # 转换API候选，处理datetime序列化
            serializable_candidates = []
            for candidate in self.api_candidates:
                candidate_dict = asdict(candidate)
                # 转换datetime为字符串
                if 'timestamp' in candidate_dict:
                    candidate_dict['timestamp'] = candidate_dict['timestamp'].isoformat()
                serializable_candidates.append(candidate_dict)

            knowledge = {
                'metadata': {
                    'export_time': datetime.now().isoformat(),
                    'learner_version': '1.0.0',
                    'total_patterns': len(self.learned_patterns)
                },
                'learned_patterns': [asdict(p) for p in self.learned_patterns],
                'api_candidates': serializable_candidates,
                'learning_stats': self.learning_stats,
                'config': self.config
            }

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(knowledge, f, indent=2, ensure_ascii=False)

            self.logger.info(f"学习知识已导出到: {output_path}")
            return True

        except Exception as e:
            self.logger.error(f"导出学习知识失败: {e}")
            return False

    def import_learned_knowledge(self, input_path: str) -> bool:
        """导入学习到的知识"""
        try:
            with open(input_path, 'r', encoding='utf-8') as f:
                knowledge = json.load(f)

            # 导入学习到的模式
            if 'learned_patterns' in knowledge:
                imported_patterns = []
                for pattern_data in knowledge['learned_patterns']:
                    pattern = LearnedPattern(**pattern_data)
                    imported_patterns.append(pattern)

                self.learned_patterns.extend(imported_patterns)
                self.logger.info(f"导入了 {len(imported_patterns)} 个学习模式")

            # 导入API候选
            if 'api_candidates' in knowledge:
                imported_candidates = []
                for candidate_data in knowledge['api_candidates']:
                    # 处理datetime字段
                    if 'timestamp' in candidate_data:
                        candidate_data['timestamp'] = datetime.fromisoformat(candidate_data['timestamp'])
                    candidate = APICandidate(**candidate_data)
                    imported_candidates.append(candidate)

                self.api_candidates.extend(imported_candidates)
                self.logger.info(f"导入了 {len(imported_candidates)} 个API候选")

            return True

        except Exception as e:
            self.logger.error(f"导入学习知识失败: {e}")
            return False


def main():
    """主函数 - 用于测试和独立运行"""
    import argparse

    parser = argparse.ArgumentParser(description='金融API增强学习引擎')
    parser.add_argument('--input', '-i', required=True, help='输入的mitm文件路径')
    parser.add_argument('--output', '-o', default='learned_knowledge.json', help='输出的学习知识文件')
    parser.add_argument('--feature-lib', '-f', help='特征库文件路径')
    parser.add_argument('--verbose', '-v', action='store_true', help='详细输出')

    args = parser.parse_args()

    # 配置日志
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # 初始化学习引擎
    learner = FinancialAPILearner(args.feature_lib)

    # 读取mitm文件
    sys.path.append('mitmproxy2swagger/mitmproxy2swagger')
    from mitmproxy_capture_reader import MitmproxyCaptureReader

    try:
        print(f"🔍 读取mitm文件: {args.input}")
        capture_reader = MitmproxyCaptureReader(args.input)

        # 转换为流数据格式
        flows = []
        for flow_wrapper in capture_reader.captured_requests():
            try:
                flow_data = {
                    'url': flow_wrapper.get_url(),
                    'method': flow_wrapper.get_method(),
                    'status_code': flow_wrapper.get_response_status_code(),
                    'response_body': flow_wrapper.get_response_body().decode('utf-8', errors='ignore') if flow_wrapper.get_response_body() else '',
                    'request_body': flow_wrapper.get_request_body().decode('utf-8', errors='ignore') if flow_wrapper.get_request_body() else ''
                }
                flows.append(flow_data)
            except Exception as e:
                continue

        print(f"✅ 成功读取 {len(flows)} 个流数据")

        # 执行学习
        print("🚀 开始增强学习...")
        report = learner.learn_from_flows(flows)

        # 输出结果
        if report['success']:
            print("🎉 学习完成！")
            print(f"📊 扫描总数: {report['stats']['total_scanned']}")
            print(f"🎯 候选API: {report['stats']['candidates_found']}")
            print(f"📚 学习模式: {report['stats']['patterns_learned']}")
            print(f"🔄 特征库更新: {report['stats']['feature_library_updates']}")

            # 导出学习知识
            if learner.export_learned_knowledge(args.output):
                print(f"💾 学习知识已保存到: {args.output}")
        else:
            print(f"❌ 学习失败: {report.get('error', 'Unknown error')}")

    except Exception as e:
        print(f"❌ 处理失败: {e}")
        return 1

    return 0


if __name__ == '__main__':
    exit(main())
