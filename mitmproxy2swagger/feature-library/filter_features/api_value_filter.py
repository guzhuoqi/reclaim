#!/usr/bin/env python3
"""
API价值过滤器
API Value Filter

用于过滤无价值的静态资源API，提高有价值API识别的准确性

核心功能：
1. 识别并过滤静态资源文件(CSS、JS、图片等)
2. 调整API价值评分权重
3. 提供严格排除规则
4. 增强银行等金融机构的核心API识别
"""

import json
import re
import logging
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from urllib.parse import urlparse


class APIValueFilter:
    """API价值过滤器"""
    
    def __init__(self, filter_config_path: str = None):
        """初始化过滤器
        
        Args:
            filter_config_path: 过滤配置文件路径，默认为同目录下的static_resource_filters.json
        """
        if filter_config_path is None:
            filter_config_path = Path(__file__).parent / "static_resource_filters.json"
        
        self.filter_config_path = Path(filter_config_path)
        self.filter_config = {}
        
        # 设置日志
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # 加载过滤配置
        self.load_filter_config()
        
    def load_filter_config(self) -> bool:
        """加载过滤配置"""
        try:
            if not self.filter_config_path.exists():
                self.logger.error(f"过滤配置文件不存在: {self.filter_config_path}")
                return False
                
            with open(self.filter_config_path, 'r', encoding='utf-8') as f:
                self.filter_config = json.load(f)
                
            self.logger.info(f"过滤配置加载成功: {self.filter_config_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"加载过滤配置失败: {e}")
            return False
            
    def is_static_resource(self, url: str) -> Tuple[bool, str, int]:
        """检查URL是否为静态资源
        
        Args:
            url: 要检查的URL
            
        Returns:
            Tuple[bool, str, int]: (是否为静态资源, 匹配的类型, 权重调整值)
        """
        if not self.filter_config:
            return False, "", 0
            
        parsed_url = urlparse(url.lower())
        path = parsed_url.path
        
        # 检查静态资源模式
        static_patterns = self.filter_config.get('static_resource_patterns', {})
        
        for resource_type, config in static_patterns.items():
            patterns = config.get('patterns', [])
            exclusion_weight = config.get('exclusion_weight', 0)
            
            for pattern in patterns:
                try:
                    if re.search(pattern, path, re.IGNORECASE):
                        return True, resource_type, exclusion_weight
                except re.error:
                    continue
                    
        # 检查低价值API模式
        low_value_patterns = self.filter_config.get('low_value_api_patterns', {})
        
        for pattern_type, config in low_value_patterns.items():
            patterns = config.get('patterns', [])
            exclusion_weight = config.get('exclusion_weight', 0)
            
            for pattern in patterns:
                try:
                    if re.search(pattern, url, re.IGNORECASE):
                        return True, pattern_type, exclusion_weight
                except re.error:
                    continue
                    
        return False, "", 0
        
    def should_strictly_exclude(self, url: str) -> bool:
        """检查URL是否应该被严格排除
        
        Args:
            url: 要检查的URL
            
        Returns:
            bool: 是否应该严格排除
        """
        if not self.filter_config:
            return False
            
        strict_rules = self.filter_config.get('filtering_rules', {}).get('strict_exclusions', {})
        patterns = strict_rules.get('patterns', [])
        
        parsed_url = urlparse(url.lower())
        path = parsed_url.path
        
        for pattern in patterns:
            try:
                if re.search(pattern, path, re.IGNORECASE):
                    return True
            except re.error:
                continue
                
        return False
        
    def get_value_bonus(self, url: str, response_content: str = "") -> Tuple[int, List[str]]:
        """计算API价值加分
        
        Args:
            url: API URL
            response_content: 响应内容
            
        Returns:
            Tuple[int, List[str]]: (加分值, 匹配的高价值模式列表)
        """
        if not self.filter_config:
            return 0, []
            
        total_bonus = 0
        matched_patterns = []
        
        high_value_patterns = self.filter_config.get('high_value_api_indicators', {})
        
        for pattern_type, config in high_value_patterns.items():
            patterns = config.get('patterns', [])
            bonus_weight = config.get('bonus_weight', 0)
            
            for pattern in patterns:
                try:
                    # 检查URL和响应内容
                    if re.search(pattern, url, re.IGNORECASE) or \
                       (response_content and re.search(pattern, response_content, re.IGNORECASE)):
                        total_bonus += bonus_weight
                        matched_patterns.append(f"{pattern_type}:{pattern}")
                        break  # 每个类型只加一次分
                except re.error:
                    continue
                    
        return total_bonus, matched_patterns
        
    def filter_and_score_api(self, url: str, original_score: int, 
                           response_content: str = "") -> Dict[str, Any]:
        """过滤并重新评分API
        
        Args:
            url: API URL
            original_score: 原始评分
            response_content: 响应内容
            
        Returns:
            Dict: 过滤结果
        """
        result = {
            'url': url,
            'original_score': original_score,
            'should_exclude': False,
            'exclusion_reason': '',
            'adjusted_score': original_score,
            'score_adjustments': [],
            'is_high_value': False,
            'final_recommendation': 'keep'
        }
        
        # 1. 检查是否应该严格排除
        if self.should_strictly_exclude(url):
            result.update({
                'should_exclude': True,
                'exclusion_reason': 'strict_exclusion_rule',
                'adjusted_score': 0,
                'final_recommendation': 'exclude'
            })
            return result
            
        # 2. 检查是否为静态资源
        is_static, resource_type, exclusion_weight = self.is_static_resource(url)
        if is_static:
            result['score_adjustments'].append({
                'type': 'static_resource_penalty',
                'category': resource_type,
                'weight_change': exclusion_weight
            })
            result['adjusted_score'] += exclusion_weight
            
        # 3. 计算价值加分
        bonus_score, matched_patterns = self.get_value_bonus(url, response_content)
        if bonus_score > 0:
            result['score_adjustments'].append({
                'type': 'high_value_bonus',
                'matched_patterns': matched_patterns,
                'weight_change': bonus_score
            })
            result['adjusted_score'] += bonus_score
            
        # 4. 确定最终建议
        filtering_rules = self.filter_config.get('filtering_rules', {})
        weighted_scoring = filtering_rules.get('weighted_scoring', {})
        
        min_threshold = weighted_scoring.get('minimum_threshold_after_filtering', 15)
        high_value_threshold = weighted_scoring.get('high_value_threshold', 30)
        
        if result['adjusted_score'] < min_threshold:
            result['final_recommendation'] = 'exclude'
            result['should_exclude'] = True
            result['exclusion_reason'] = 'below_minimum_threshold'
        elif result['adjusted_score'] >= high_value_threshold:
            result['is_high_value'] = True
            result['final_recommendation'] = 'high_priority'
        else:
            result['final_recommendation'] = 'keep'
            
        return result
        
    def batch_filter_apis(self, apis: List[Dict[str, Any]]) -> Dict[str, Any]:
        """批量过滤API列表
        
        Args:
            apis: API列表，每个API应包含 url, score 等字段
            
        Returns:
            Dict: 批量过滤结果
        """
        results = {
            'total_apis': len(apis),
            'excluded_apis': [],
            'kept_apis': [],
            'high_value_apis': [],
            'filtering_summary': {
                'static_resources_excluded': 0,
                'below_threshold_excluded': 0,
                'strict_exclusions': 0,
                'high_value_promoted': 0
            }
        }
        
        for api in apis:
            url = api.get('url', '')
            original_score = api.get('score', 0)
            response_content = api.get('response_content', '')
            
            filter_result = self.filter_and_score_api(url, original_score, response_content)
            
            # 更新API信息
            api.update({
                'filter_result': filter_result,
                'adjusted_score': filter_result['adjusted_score'],
                'is_filtered': filter_result['should_exclude']
            })
            
            # 分类统计
            if filter_result['should_exclude']:
                results['excluded_apis'].append(api)
                
                # 统计排除原因
                if filter_result['exclusion_reason'] == 'strict_exclusion_rule':
                    results['filtering_summary']['strict_exclusions'] += 1
                elif filter_result['exclusion_reason'] == 'below_minimum_threshold':
                    results['filtering_summary']['below_threshold_excluded'] += 1
                    
                # 检查是否因为静态资源被排除
                if any(adj['type'] == 'static_resource_penalty' 
                      for adj in filter_result['score_adjustments']):
                    results['filtering_summary']['static_resources_excluded'] += 1
                    
            else:
                results['kept_apis'].append(api)
                
                if filter_result['is_high_value']:
                    results['high_value_apis'].append(api)
                    results['filtering_summary']['high_value_promoted'] += 1
                    
        return results
        
    def get_filtering_statistics(self, filtering_results: Dict[str, Any]) -> str:
        """生成过滤统计报告
        
        Args:
            filtering_results: 批量过滤结果
            
        Returns:
            str: 统计报告
        """
        total = filtering_results['total_apis']
        excluded = len(filtering_results['excluded_apis'])
        kept = len(filtering_results['kept_apis'])
        high_value = len(filtering_results['high_value_apis'])
        
        summary = filtering_results['filtering_summary']
        
        report = f"""
📊 API过滤统计报告
==================
总API数量: {total}
保留API: {kept} ({kept/total*100:.1f}%)
排除API: {excluded} ({excluded/total*100:.1f}%)
高价值API: {high_value} ({high_value/total*100:.1f}%)

📋 排除详情:
- 静态资源排除: {summary['static_resources_excluded']}
- 评分过低排除: {summary['below_threshold_excluded']}
- 严格规则排除: {summary['strict_exclusions']}
- 高价值提升: {summary['high_value_promoted']}

💡 过滤效果:
原始识别准确率: {(5/total)*100:.1f}% (5个真实API / {total}个总API)
过滤后准确率: {(min(5, high_value)/kept*100) if kept > 0 else 0:.1f}% (预估)
"""
        return report
        
    def export_filtered_patterns(self, filtering_results: Dict[str, Any], 
                                output_file: str = None) -> str:
        """导出过滤后的API模式
        
        Args:
            filtering_results: 过滤结果
            output_file: 输出文件路径
            
        Returns:
            str: 输出文件路径
        """
        if output_file is None:
            output_file = "filtered_api_patterns.json"
            
        # 提取高价值API模式
        high_value_patterns = []
        for api in filtering_results['high_value_apis']:
            parsed_url = urlparse(api['url'])
            pattern_info = {
                'url': api['url'],
                'path': parsed_url.path,
                'domain': parsed_url.netloc,
                'original_score': api.get('score', 0),
                'adjusted_score': api['adjusted_score'],
                'score_adjustments': api['filter_result']['score_adjustments']
            }
            high_value_patterns.append(pattern_info)
            
        # 提取被排除的静态资源模式
        excluded_static_patterns = []
        for api in filtering_results['excluded_apis']:
            if any(adj['type'] == 'static_resource_penalty' 
                  for adj in api['filter_result']['score_adjustments']):
                parsed_url = urlparse(api['url'])
                pattern_info = {
                    'url': api['url'],
                    'path': parsed_url.path,
                    'exclusion_reason': api['filter_result']['exclusion_reason'],
                    'resource_category': next(
                        (adj['category'] for adj in api['filter_result']['score_adjustments'] 
                         if adj['type'] == 'static_resource_penalty'), 'unknown'
                    )
                }
                excluded_static_patterns.append(pattern_info)
                
        export_data = {
            'metadata': {
                'export_date': 'now',
                'total_apis_analyzed': filtering_results['total_apis'],
                'high_value_apis_found': len(high_value_patterns),
                'static_resources_excluded': len(excluded_static_patterns)
            },
            'high_value_api_patterns': high_value_patterns,
            'excluded_static_patterns': excluded_static_patterns,
            'filtering_summary': filtering_results['filtering_summary']
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
            
        return output_file


def main():
    """命令行测试接口"""
    import argparse
    
    parser = argparse.ArgumentParser(description='API价值过滤器测试')
    parser.add_argument('--test-url', '-u', help='测试单个URL')
    parser.add_argument('--config', '-c', help='过滤配置文件路径')
    
    args = parser.parse_args()
    
    # 创建过滤器
    filter_instance = APIValueFilter(args.config)
    
    if args.test_url:
        # 测试单个URL
        result = filter_instance.filter_and_score_api(args.test_url, 20)
        print(f"URL: {args.test_url}")
        print(f"过滤结果: {json.dumps(result, indent=2, ensure_ascii=False)}")
    else:
        # 测试示例API列表
        test_apis = [
            {'url': 'https://its.bochk.com/acc.overview.do', 'score': 20},
            {'url': 'https://www.cmbwinglungbank.com/js/jquery-3.2.1.min.js', 'score': 15},
            {'url': 'https://its.bochk.com/images/common/nav/nav1_corner.gif', 'score': 10},
            {'url': 'https://www.cmbwinglungbank.com/ibanking/McpCSReqServlet', 'score': 25},
            {'url': 'https://its.bochk.com/css/promote.css', 'score': 12}
        ]
        
        results = filter_instance.batch_filter_apis(test_apis)
        print(filter_instance.get_filtering_statistics(results))


if __name__ == "__main__":
    main()