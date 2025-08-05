#!/usr/bin/env python3
"""
插件管理器 - mitmproxy2swagger扩展插件管理
Plugin Manager - Extension Plugin Management for mitmproxy2swagger

负责管理和协调所有mitmproxy2swagger插件的加载、注册和执行。
提供统一的插件接口，支持动态加载和配置。

核心功能：
1. 插件发现和加载
2. 插件注册到mitmproxy2swagger系统
3. 插件配置管理
4. 插件执行协调
5. 插件状态监控
"""

import os
import sys
import json
import logging
import importlib
from typing import Dict, List, Any, Optional, Type
from pathlib import Path
from dataclasses import dataclass
from abc import ABC, abstractmethod


@dataclass
class PluginInfo:
    """插件信息"""
    name: str
    version: str
    description: str
    author: str
    capabilities: List[str]
    config_path: Optional[str] = None
    enabled: bool = True


class PluginInterface(ABC):
    """插件接口定义"""
    
    @abstractmethod
    def get_plugin_info(self) -> Dict[str, Any]:
        """获取插件信息"""
        pass
    
    @abstractmethod
    def register_to_mitmproxy2swagger(self) -> bool:
        """注册到mitmproxy2swagger系统"""
        pass


class PluginManager:
    """插件管理器"""
    
    def __init__(self, plugins_dir: str = None):
        """初始化插件管理器
        
        Args:
            plugins_dir: 插件目录路径
        """
        if plugins_dir is None:
            plugins_dir = Path(__file__).parent
        
        self.plugins_dir = Path(plugins_dir)
        self.plugins: Dict[str, Any] = {}
        self.plugin_configs: Dict[str, Dict] = {}
        
        # 设置日志
        self.logger = logging.getLogger(__name__)
        
        # 加载插件配置
        self.load_plugin_configs()
        
    def load_plugin_configs(self):
        """加载插件配置"""
        config_file = self.plugins_dir / "plugins_config.json"
        
        try:
            if config_file.exists():
                with open(config_file, 'r', encoding='utf-8') as f:
                    self.plugin_configs = json.load(f)
                self.logger.info(f"✅ 插件配置加载成功: {config_file}")
            else:
                # 创建默认配置
                default_config = {
                    "feature_library_plugin": {
                        "enabled": True,
                        "config_path": "../ai_analysis_features/financial_api_features.json",
                        "priority": 1
                    }
                }
                
                with open(config_file, 'w', encoding='utf-8') as f:
                    json.dump(default_config, f, indent=2, ensure_ascii=False)
                
                self.plugin_configs = default_config
                self.logger.info(f"✅ 创建默认插件配置: {config_file}")
                
        except Exception as e:
            self.logger.error(f"❌ 插件配置加载失败: {e}")
            self.plugin_configs = {}
    
    def discover_plugins(self) -> List[str]:
        """发现可用的插件"""
        plugins = []
        
        # 扫描插件目录中的Python文件
        for file_path in self.plugins_dir.glob("*_plugin.py"):
            if file_path.name != "__init__.py":
                plugin_name = file_path.stem
                plugins.append(plugin_name)
                self.logger.info(f"🔍 发现插件: {plugin_name}")
        
        return plugins
    
    def load_plugin(self, plugin_name: str) -> bool:
        """加载单个插件
        
        Args:
            plugin_name: 插件名称
            
        Returns:
            bool: 是否加载成功
        """
        try:
            # 检查插件是否已启用
            plugin_config = self.plugin_configs.get(plugin_name, {})
            if not plugin_config.get("enabled", True):
                self.logger.info(f"⏭️  插件已禁用，跳过加载: {plugin_name}")
                return False
            
            # 动态导入插件模块
            module_name = f"plugins.{plugin_name}"
            
            # 添加插件目录到Python路径
            if str(self.plugins_dir.parent) not in sys.path:
                sys.path.insert(0, str(self.plugins_dir.parent))
            
            plugin_module = importlib.import_module(module_name)
            
            # 查找插件类或初始化函数
            plugin_instance = None
            
            # 方法1: 查找全局插件实例
            if hasattr(plugin_module, f"{plugin_name.replace('_plugin', '')}_plugin"):
                plugin_instance = getattr(plugin_module, f"{plugin_name.replace('_plugin', '')}_plugin")
            
            # 方法2: 查找初始化函数
            elif hasattr(plugin_module, "initialize_plugin"):
                config_path = plugin_config.get("config_path")
                if config_path and not os.path.isabs(config_path):
                    config_path = str(self.plugins_dir / config_path)
                
                success = plugin_module.initialize_plugin(config_path)
                if success and hasattr(plugin_module, f"{plugin_name.replace('_plugin', '')}_plugin"):
                    plugin_instance = getattr(plugin_module, f"{plugin_name.replace('_plugin', '')}_plugin")
            
            # 方法3: 查找插件类
            else:
                for attr_name in dir(plugin_module):
                    attr = getattr(plugin_module, attr_name)
                    if (isinstance(attr, type) and 
                        hasattr(attr, 'get_plugin_info') and 
                        hasattr(attr, 'register_to_mitmproxy2swagger')):
                        plugin_instance = attr()
                        break
            
            if plugin_instance:
                self.plugins[plugin_name] = plugin_instance
                self.logger.info(f"✅ 插件加载成功: {plugin_name}")
                return True
            else:
                self.logger.error(f"❌ 插件加载失败，未找到有效的插件实例: {plugin_name}")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ 插件加载失败 {plugin_name}: {e}")
            return False
    
    def register_all_plugins(self) -> Dict[str, bool]:
        """注册所有已加载的插件到mitmproxy2swagger系统
        
        Returns:
            Dict[str, bool]: 每个插件的注册结果
        """
        results = {}
        
        # 按优先级排序插件
        sorted_plugins = sorted(
            self.plugins.items(),
            key=lambda x: self.plugin_configs.get(x[0], {}).get("priority", 999)
        )
        
        for plugin_name, plugin_instance in sorted_plugins:
            try:
                if hasattr(plugin_instance, 'register_to_mitmproxy2swagger'):
                    success = plugin_instance.register_to_mitmproxy2swagger()
                    results[plugin_name] = success
                    
                    if success:
                        self.logger.info(f"✅ 插件注册成功: {plugin_name}")
                    else:
                        self.logger.error(f"❌ 插件注册失败: {plugin_name}")
                else:
                    self.logger.warning(f"⚠️  插件缺少注册方法: {plugin_name}")
                    results[plugin_name] = False
                    
            except Exception as e:
                self.logger.error(f"❌ 插件注册异常 {plugin_name}: {e}")
                results[plugin_name] = False
        
        return results
    
    def get_plugin_info(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """获取插件信息
        
        Args:
            plugin_name: 插件名称
            
        Returns:
            插件信息字典，如果插件不存在返回None
        """
        plugin_instance = self.plugins.get(plugin_name)
        if plugin_instance and hasattr(plugin_instance, 'get_plugin_info'):
            return plugin_instance.get_plugin_info()
        return None
    
    def list_plugins(self) -> Dict[str, Dict[str, Any]]:
        """列出所有插件及其状态"""
        plugin_list = {}
        
        for plugin_name, plugin_instance in self.plugins.items():
            info = self.get_plugin_info(plugin_name)
            config = self.plugin_configs.get(plugin_name, {})
            
            plugin_list[plugin_name] = {
                "info": info,
                "config": config,
                "loaded": True,
                "enabled": config.get("enabled", True)
            }
        
        return plugin_list
    
    def initialize_all_plugins(self) -> Dict[str, bool]:
        """初始化所有插件（发现、加载、注册）
        
        Returns:
            Dict[str, bool]: 每个插件的初始化结果
        """
        results = {}
        
        self.logger.info("🚀 开始初始化所有插件...")
        
        # 1. 发现插件
        discovered_plugins = self.discover_plugins()
        self.logger.info(f"🔍 发现 {len(discovered_plugins)} 个插件")
        
        # 2. 加载插件
        for plugin_name in discovered_plugins:
            load_success = self.load_plugin(plugin_name)
            results[plugin_name] = load_success
        
        # 3. 注册插件
        registration_results = self.register_all_plugins()
        
        # 合并结果
        for plugin_name, reg_success in registration_results.items():
            if plugin_name in results:
                results[plugin_name] = results[plugin_name] and reg_success
        
        # 统计结果
        successful_plugins = sum(1 for success in results.values() if success)
        total_plugins = len(results)
        
        self.logger.info(f"🎉 插件初始化完成: {successful_plugins}/{total_plugins} 成功")
        
        return results
    
    def get_status_report(self) -> Dict[str, Any]:
        """获取插件管理器状态报告"""
        return {
            "plugins_dir": str(self.plugins_dir),
            "total_plugins": len(self.plugins),
            "loaded_plugins": list(self.plugins.keys()),
            "plugin_configs": self.plugin_configs,
            "plugins_info": self.list_plugins()
        }


# 全局插件管理器实例
plugin_manager = PluginManager()


def initialize_plugin_system(plugins_dir: str = None) -> bool:
    """初始化插件系统
    
    Args:
        plugins_dir: 插件目录路径
        
    Returns:
        bool: 是否初始化成功
    """
    global plugin_manager
    
    try:
        if plugins_dir:
            plugin_manager = PluginManager(plugins_dir)
        
        # 初始化所有插件
        results = plugin_manager.initialize_all_plugins()
        
        # 检查是否有插件成功初始化
        successful_plugins = [name for name, success in results.items() if success]
        
        if successful_plugins:
            print(f"🎉 插件系统初始化成功！")
            print(f"✅ 成功加载的插件: {', '.join(successful_plugins)}")
            return True
        else:
            print("⚠️  插件系统初始化完成，但没有插件成功加载")
            return False
            
    except Exception as e:
        print(f"❌ 插件系统初始化失败: {e}")
        return False


def main():
    """命令行测试接口"""
    import argparse
    
    parser = argparse.ArgumentParser(description='插件管理器测试')
    parser.add_argument('--plugins-dir', '-d', help='插件目录路径')
    parser.add_argument('--list', '-l', action='store_true', help='列出所有插件')
    parser.add_argument('--status', '-s', action='store_true', help='显示状态报告')
    
    args = parser.parse_args()
    
    # 初始化插件系统
    if initialize_plugin_system(args.plugins_dir):
        if args.list:
            print("\n📋 插件列表:")
            plugins = plugin_manager.list_plugins()
            for name, details in plugins.items():
                info = details.get("info", {})
                print(f"  🔌 {name}")
                print(f"     版本: {info.get('version', 'N/A')}")
                print(f"     描述: {info.get('description', 'N/A')}")
                print(f"     状态: {'启用' if details.get('enabled') else '禁用'}")
        
        if args.status:
            print("\n📊 状态报告:")
            status = plugin_manager.get_status_report()
            print(json.dumps(status, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
