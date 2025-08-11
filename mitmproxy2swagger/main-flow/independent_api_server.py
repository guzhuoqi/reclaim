#!/usr/bin/env python3
"""
独立的银行Provider生成API服务器
完全独立于mitmproxy，提供REST API接口来运行主流程

功能：
1. 异步执行主流程
2. 实时状态跟踪
3. 文件上传和管理
4. 结果查询和下载
5. 错误处理和日志记录

API端点：
- GET /status - 查询当前状态
- POST /reset - 重置状态
- POST /trigger - 触发主流程（在线模式）
- POST /upload-and-trigger - 上传mitm文件并触发流程（离线模式）
- GET /providers - 获取最新的Provider列表
- GET /results/{file_id} - 下载结果文件
- GET /files - 列出所有输出文件
- GET /health - 健康检查
"""

import os
import json
import asyncio
import uuid
import time
import shutil
import socket
import subprocess
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import logging

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks, Body
from http import HTTPStatus
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
try:
    # Pydantic v2
    from pydantic import RootModel  # type: ignore
except Exception:  # pragma: no cover
    RootModel = None  # type: ignore
import uvicorn

# 导入主流程相关模块
from integrated_main_pipeline import IntegratedMainPipeline
from dynamic_config import dynamic_config
from pathlib import Path
from collections import OrderedDict
from urllib.parse import urlparse

# Task Session 数据库
try:
    from ..mitmproxy_addons.task_session_db import TaskSessionDB  # 当作模块引用运行
except Exception:
    # 直接运行该文件时，使用绝对路径导入
    import sys
    CURRENT_DIR = Path(__file__).resolve().parent
    PROJECT_ROOT = CURRENT_DIR.parent  # mitmproxy2swagger
    ADDONS_DIR = PROJECT_ROOT / "mitmproxy_addons"
    if str(ADDONS_DIR) not in sys.path:
        sys.path.insert(0, str(ADDONS_DIR))
    from task_session_db import TaskSessionDB  # type: ignore
try:
    from ..mitmproxy_addons.attestor_db import AttestorDB  # 当作模块引用运行
except Exception:
    # 同步添加 addons 目录到路径后再导入
    from attestor_db import AttestorDB  # type: ignore



# 确保logs目录存在
os.makedirs('logs', exist_ok=True)

# 配置日志 - 所有日志文件写入logs目录
from datetime import datetime
log_filename = f'logs/api_server_{datetime.now().strftime("%Y%m%d")}.log'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_filename),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# 获取真实的mitm配置用于API文档显示
def get_real_mitm_config():
    """获取真实的mitm配置，用于API文档默认值"""
    try:
        dynamic_config.discover_running_mitmproxy()
        real_host = dynamic_config.get_mitm_host()
        real_port = dynamic_config.get_mitm_port()
        return real_host, real_port
    except Exception:
        return "127.0.0.1", 8080  # fallback默认值

# 获取真实配置
REAL_MITM_HOST, REAL_MITM_PORT = get_real_mitm_config()

# Pydantic模型
class TriggerRequest(BaseModel):
    mitm_host: Optional[str] = Field(
        default=REAL_MITM_HOST,
        description="mitmproxy主机地址（自动发现的真实地址）",
        example=REAL_MITM_HOST
    )
    mitm_port: Optional[int] = Field(
        default=REAL_MITM_PORT,
        description="mitmproxy端口（自动发现的真实端口）",
        example=REAL_MITM_PORT
    )
    output_dir: Optional[str] = Field(
        default="data",
        description="输出目录",
        example="data"
    )

    def __init__(self, **data):
        super().__init__(**data)
        # 自动发现并填充真实的mitm配置
        try:
            dynamic_config.discover_running_mitmproxy()
            self.mitm_host = dynamic_config.get_mitm_host()
            self.mitm_port = dynamic_config.get_mitm_port()
            logger.info(f"🔄 自动填充真实mitm配置: {self.mitm_host}:{self.mitm_port}")
        except Exception as e:
            logger.warning(f"⚠️  无法自动填充mitm配置: {e}")
            # 保持原有值


class OfflineTriggerRequest(BaseModel):
    input_file: str  # 必需：离线模式下的输入文件路径
    output_dir: Optional[str] = "data"

    def __init__(self, **data):
        # 如果没有提供mitm配置，在运行时使用动态配置
        if 'mitm_host' not in data or data['mitm_host'] is None:
            data['mitm_host'] = dynamic_config.get_mitm_host()
        if 'mitm_port' not in data or data['mitm_port'] is None:
            data['mitm_port'] = dynamic_config.get_mitm_port()
        super().__init__(**data)

class StatusResponse(BaseModel):
    success: bool
    data: Dict[str, Any]
    message: str = ""

class APIResponse(BaseModel):
    success: bool
    message: str
    data: Dict[str, Any] = {}


# 全局状态管理
class ServerState:
    def __init__(self):
        self.reset()

    def reset(self):
        self.status = "idle"  # idle, running, completed, error
        self.progress = 0
        self.message = "服务器已就绪"
        self.current_task_id = None
        self.start_time = None
        self.end_time = None
        self.result_files = []
        self.errors = []
        self.pipeline_result = None
        self.running_config = {}

# 全局状态实例
server_state = ServerState()


# FastAPI应用
app = FastAPI(
    title="银行Provider生成API服务",
    description="独立的银行Provider生成服务，从mitmproxy抓包文件生成Reclaim协议标准配置",
    version="1.0.0"
)

# CORS配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 确保必要目录存在
def ensure_directories():
    """确保必要的目录存在"""
    dirs = ["data", "temp", "uploads"]
    for dir_name in dirs:
        os.makedirs(dir_name, exist_ok=True)
        logger.info(f"确保目录存在: {dir_name}")

ensure_directories()



def sort_providers_by_time(providers_array: List[Dict], reverse: bool = True) -> List[Dict]:
    """统一的Provider排序函数

    Args:
        providers_array: Provider数组
        reverse: True为倒序（最新在前），False为正序

    Returns:
        排序后的Provider数组
    """
    from datetime import datetime, timezone

    def get_provider_timestamp(provider):
        try:
            # 从metadata中获取生成时间
            generated_at = provider.get('providerConfig', {}).get('providerConfig', {}).get('metadata', {}).get('generated_at', '')
            if generated_at:
                # 解析ISO格式时间戳，确保时区一致
                dt = datetime.fromisoformat(generated_at.replace('Z', '+00:00'))
                # 如果是timezone-aware，转换为UTC
                if dt.tzinfo is not None:
                    return dt.astimezone(timezone.utc).replace(tzinfo=None)
                return dt
            else:
                # 如果没有时间戳，使用当前时间（timezone-naive）
                return datetime.now()
        except:
            # 解析失败时使用当前时间（timezone-naive）
            return datetime.now()

    # 按时间排序
    return sorted(providers_array, key=get_provider_timestamp, reverse=reverse)


def get_local_ip() -> str:
    """动态获取本机IP地址"""
    try:
        # 方法1: 连接到远程地址获取本地IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        pass

    try:
        # 方法2: 通过ifconfig获取活跃网络接口的IP
        result = subprocess.run(
            ["ifconfig"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if 'inet ' in line and '127.0.0.1' not in line and 'broadcast' in line:
                    parts = line.strip().split()
                    for i, part in enumerate(parts):
                        if part == "inet" and i + 1 < len(parts):
                            ip = parts[i + 1]
                            # 优先返回192.168.x.x或10.x.x.x的内网IP
                            if ip.startswith(('192.168.', '10.', '172.')):
                                return ip
    except Exception:
        pass

    try:
        # 方法3: 通过hostname获取
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
    except Exception:
        pass

    # 备用方案: 返回localhost
    return "127.0.0.1"


############################################
# 域名 -> 首页链接 配置 持久化与API
############################################

DOMAIN_HOMEPAGES_FILE = os.path.join("data", "domain_homepages.json")


def _load_domain_homepages() -> Dict[str, str]:
    try:
        if os.path.exists(DOMAIN_HOMEPAGES_FILE):
            with open(DOMAIN_HOMEPAGES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                # 仅保留str->str
                if isinstance(data, dict):
                    return {str(k): str(v) for k, v in data.items()}
        return {}
    except Exception as e:
        logger.warning(f"读取域名首页配置失败: {e}")
        return {}


def _save_domain_homepages(mapping: Dict[str, str]) -> None:
    os.makedirs(os.path.dirname(DOMAIN_HOMEPAGES_FILE), exist_ok=True)
    with open(DOMAIN_HOMEPAGES_FILE, "w", encoding="utf-8") as f:
        json.dump(mapping, f, ensure_ascii=False, indent=2)


def _extract_login_url_from_provider(provider: Dict[str, Any]) -> Optional[str]:
    try:
        if not isinstance(provider, dict):
            return None
        # 常见路径优先：provider.providerConfig.providerConfig.loginUrl
        pc = provider.get("providerConfig")
        if isinstance(pc, dict):
            inner = pc.get("providerConfig")
            if isinstance(inner, dict) and isinstance(inner.get("loginUrl"), str):
                return inner.get("loginUrl")
            if isinstance(pc.get("loginUrl"), str):
                return pc.get("loginUrl")
        if isinstance(provider.get("loginUrl"), str):
            return provider.get("loginUrl")
    except Exception:
        return None
    return None


def _set_login_url_in_provider(provider: Dict[str, Any], new_url: str) -> bool:
    try:
        if not isinstance(provider, dict):
            return False
        pc = provider.get("providerConfig")
        if isinstance(pc, dict):
            inner = pc.get("providerConfig")
            if isinstance(inner, dict):
                inner["loginUrl"] = new_url
                return True
            # 退化路径
            pc["loginUrl"] = new_url
            return True
        # 根层兜底
        provider["loginUrl"] = new_url
        return True
    except Exception:
        return False


def _get_homepage_for_url(url: str, mapping: Dict[str, str]) -> Optional[str]:
    try:
        if not url or not isinstance(url, str):
            return None
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if not host:
            return None
        # 优先精确匹配
        if host in mapping:
            return mapping[host]
        # 子域匹配：host 以 .domain 结尾
        for domain, homepage in mapping.items():
            d = (domain or "").lower().strip()
            if not d:
                continue
            if host == d or host.endswith("." + d):
                return homepage
        return None
    except Exception:
        return None


if RootModel:
    class DomainHomepagePayload(RootModel[Dict[str, str]]):  # type: ignore
        """Pydantic v2 RootModel: 请求体必须是仅包含一对 key/value 的对象"""

        def get_single_pair(self) -> (str, str):
            value = self.root  # type: ignore[attr-defined]
            if not isinstance(value, dict) or len(value) != 1:
                raise HTTPException(status_code=400, detail="请求体必须只包含一对域名与首页链接")
            domain, homepage = next(iter(value.items()))
            if not domain or not isinstance(domain, str):
                raise HTTPException(status_code=400, detail="无效的域名")
            if not homepage or not isinstance(homepage, str):
                raise HTTPException(status_code=400, detail="无效的首页链接")
            return domain.strip(), homepage.strip()
else:
    class DomainHomepagePayload(BaseModel):  # 兼容v1（退化为普通对象）
        mapping: Dict[str, str]

        def get_single_pair(self) -> (str, str):
            value = self.mapping
            if not isinstance(value, dict) or len(value) != 1:
                raise HTTPException(status_code=400, detail="请求体必须只包含一对域名与首页链接")
            domain, homepage = next(iter(value.items()))
            if not domain or not isinstance(domain, str):
                raise HTTPException(status_code=400, detail="无效的域名")
            if not homepage or not isinstance(homepage, str):
                raise HTTPException(status_code=400, detail="无效的首页链接")
            return domain.strip(), homepage.strip()


@app.get("/domain-homepages", response_model=APIResponse)
async def get_domain_homepages():
    """获取所有 域名→首页链接 配置"""
    mapping = _load_domain_homepages()
    return APIResponse(
        success=True,
        message="查询成功",
        data={"mappings": mapping, "count": len(mapping)}
    )


@app.get("/domain-homepages/{domain}", response_model=APIResponse)
async def get_domain_homepage(domain: str):
    mapping = _load_domain_homepages()
    if domain not in mapping:
        raise HTTPException(status_code=404, detail="未找到该域名的配置")
    return APIResponse(success=True, message="查询成功", data={"domain": domain, "homepage": mapping[domain]})


@app.post("/domain-homepages", response_model=APIResponse)
async def upsert_domain_homepage(payload: DomainHomepagePayload):
    """新增或更新一对域名→首页链接（请求体为单对映射）"""
    domain, homepage = payload.get_single_pair()
    mapping = _load_domain_homepages()
    mapping[domain] = homepage
    _save_domain_homepages(mapping)
    return APIResponse(success=True, message="保存成功", data={"domain": domain, "homepage": homepage, "mappings": mapping})


@app.delete("/domain-homepages/{domain}", response_model=APIResponse)
async def delete_domain_homepage(domain: str):
    mapping = _load_domain_homepages()
    if domain in mapping:
        mapping.pop(domain)
        _save_domain_homepages(mapping)
        return APIResponse(success=True, message="删除成功", data={"domain": domain, "mappings": mapping})
    raise HTTPException(status_code=404, detail="未找到该域名的配置")


@app.get("/ui/domain-homepages", response_class=HTMLResponse)
async def ui_domain_homepages():
    """简单内置页面：加载 main-flow/web_extension.html（含域名配置管理UI）"""
    try:
        current_dir = Path(__file__).resolve().parent
        html_path = current_dir / "web_extension.html"
        if not html_path.exists():
            return HTMLResponse("<h3>未找到内置页面</h3>", status_code=404)
        content = html_path.read_text(encoding="utf-8")
        return HTMLResponse(content)
    except Exception as e:
        logger.error(f"加载内置页面失败: {e}")
        return HTMLResponse(f"<h3>加载失败: {e}</h3>", status_code=500)


async def run_pipeline_async(config: Dict[str, Any], offline_mode: bool = False, input_file: str = None):
    """异步运行主流程"""
    global server_state

    task_id = str(uuid.uuid4())
    server_state.current_task_id = task_id
    server_state.status = "running"
    server_state.progress = 0
    server_state.message = "正在初始化主流程..."
    server_state.start_time = datetime.now()
    server_state.running_config = config
    server_state.errors = []

    logger.info(f"开始执行主流程任务: {task_id}")
    logger.info(f"配置: {config}")
    logger.info(f"离线模式: {offline_mode}, 输入文件: {input_file}")

    try:
        # 更新进度：初始化
        server_state.progress = 10
        server_state.message = "创建集成主流程管道器..."

        # 创建集成主流程实例
        pipeline = IntegratedMainPipeline(config)

        # 更新进度：开始执行
        server_state.progress = 20
        server_state.message = "开始执行集成主流程..."

        # 执行集成主流程
        result = pipeline.run_full_pipeline(
            offline_mode=offline_mode,
            input_file=input_file
        )

        # 检查结果是否有效
        if result is None:
            raise Exception("集成主流程返回了空结果")

        # 更新最终状态
        if result.get('success', False):
            server_state.status = "completed"
            server_state.progress = 100

            # 获取集成主流程的结果
            report = result.get('report', {})

            # 获取provider计数 - 适配新的集成主流程结构
            provider_results = report.get('provider_results', {})
            analysis_results = report.get('analysis_results', {})

            providers_count = provider_results.get('providers_count', 0)
            questionable_count = provider_results.get('questionable_count', 0)
            valuable_apis = analysis_results.get('valuable_apis', 0)

            server_state.message = f"集成主流程执行成功！识别 {valuable_apis} 个有价值API，成功构建 {providers_count} 个Reclaim Provider，{questionable_count} 个存疑API"
            server_state.pipeline_result = result

            # 记录输出文件 - 适配集成主流程的结构
            server_state.result_files = []

            # 从集成主流程的output_files结构获取文件列表
            output_files = result.get('output_files', {})
            if isinstance(output_files, dict):
                for file_path in output_files.values():
                    if file_path and os.path.exists(file_path):
                        server_state.result_files.append(file_path)

            # 检查data目录中的相关文件
            data_dir = config.get('output_dir', 'data')
            if os.path.exists(data_dir):
                for file in os.listdir(data_dir):
                    if file.endswith('.json') and any(prefix in file for prefix in
                        ['reclaim_providers_', 'questionable_apis_', 'feature_analysis_', 'integrated_pipeline_report_']):
                        file_path = os.path.join(data_dir, file)
                        if file_path not in server_state.result_files:
                            server_state.result_files.append(file_path)

            logger.info(f"集成主流程执行成功: {result}")
        else:
            server_state.status = "error"
            error_message = result.get('message', '未知错误') if result else '集成主流程返回空结果'
            server_state.message = f"集成主流程执行失败: {error_message}"
            server_state.errors.append(error_message)
            logger.error(f"集成主流程执行失败: {result}")

    except Exception as e:
        server_state.status = "error"
        server_state.message = f"集成主流程执行异常: {str(e)}"
        server_state.errors.append(str(e))
        logger.error(f"集成主流程执行异常: {e}", exc_info=True)

    finally:
        server_state.end_time = datetime.now()
        if server_state.start_time:
            duration = server_state.end_time - server_state.start_time
            logger.info(f"任务 {task_id} 完成，耗时: {duration}")


@app.get("/", response_class=JSONResponse)
async def root():
    """根路径，返回API信息"""
    return {
        "service": "银行Provider生成API服务",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "health": "/health",
            "status": "/status",
            "reset": "/reset",
            "trigger": "/trigger",
            "upload": "/upload-and-trigger",
            "providers": "/providers",
            "edit_provider": "/providers/{provider_id}/edit",
            "files": "/files",
            "task_sessions_create": "/task-sessions",
            "task_session_response": "/task-sessions/{session_id}/response",
            "domain_homepages": "/domain-homepages",
            "domain_homepage_item": "/domain-homepages/{domain}",
            "ui_domain_homepages": "/ui/domain-homepages"
        }
    }


@app.get("/health")
async def health_check():
    """健康检查"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "server_status": server_state.status
    }


@app.get("/status", response_model=StatusResponse)
async def get_status():
    """获取当前状态"""
    global server_state

    # 计算运行时间
    duration_seconds = None
    if server_state.start_time:
        if server_state.end_time:
            duration = server_state.end_time - server_state.start_time
        else:
            duration = datetime.now() - server_state.start_time
        duration_seconds = int(duration.total_seconds())

    status_data = {
        "status": server_state.status,
        "progress": server_state.progress,
        "message": server_state.message,
        "task_id": server_state.current_task_id,
        "start_time": server_state.start_time.isoformat() if server_state.start_time else None,
        "end_time": server_state.end_time.isoformat() if server_state.end_time else None,
        "duration_seconds": duration_seconds,
        "result_files_count": len(server_state.result_files),
        "errors": server_state.errors,
        "config": server_state.running_config
    }

    return StatusResponse(
        success=True,
        data=status_data,
        message="状态查询成功"
    )


@app.post("/reset")
async def reset_status():
    """重置服务器状态"""
    global server_state

    # 如果当前有任务在运行，不允许重置
    if server_state.status == "running":
        raise HTTPException(
            status_code=400,
            detail="当前有任务正在运行，无法重置状态"
        )

    server_state.reset()
    logger.info("服务器状态已重置")

    return APIResponse(
        success=True,
        message="服务器状态已重置",
        data={"status": server_state.status}
    )


@app.post("/trigger")
async def trigger_pipeline(request: TriggerRequest):
    """触发集成主流程（在线模式）- 从mitmproxy导出数据并执行完整流程"""
    global server_state

    # 检查是否有任务正在运行
    if server_state.status == "running":
        raise HTTPException(
            status_code=400,
            detail="已有任务正在运行，请等待当前任务完成或重置状态"
        )

    # 始终自动发现真实的mitm代理配置（忽略用户输入的参数）
    try:
        logger.info("🔍 开始自动发现真实运行的mitm代理...")

        # 强制重新发现mitm代理
        dynamic_config.discover_running_mitmproxy()

        # 获取发现的配置
        discovered_host = dynamic_config.get_mitm_host()
        discovered_port = dynamic_config.get_mitm_port()

        logger.info(f"✅ 自动发现真实mitm代理: {discovered_host}:{discovered_port}")
        logger.info(f"📝 用户提供的参数 {request.mitm_host}:{request.mitm_port} 已被自动发现的配置覆盖")

        mitm_host = discovered_host
        mitm_port = discovered_port

    except Exception as e:
        logger.error(f"❌ 自动发现失败: {e}")
        raise HTTPException(status_code=500, detail=f"无法发现运行中的mitm代理: {str(e)}")

    config = {
        'mitm_host': mitm_host,
        'mitm_port': mitm_port,
        'output_dir': request.output_dir or 'data'
    }

    logger.info(f"开始同步执行集成主流程任务（在线模式），配置: {config}")

    # 同步执行集成主流程 - 强制使用在线模式
    await run_pipeline_async(config, offline_mode=False, input_file=None)

    # 检查执行结果
    if server_state.status == "completed" and server_state.pipeline_result:
        result = server_state.pipeline_result

        # 读取生成的provider数据，直接返回给前端
        providers_response = {
            "success": True,
            "message": server_state.message,
            "providers": []
        }

        try:
            # 适配集成主流程的结果结构
            output_files = result.get('output_files', {})

            # 读取Reclaim providers数据
            providers_file = output_files.get('providers')
            if providers_file and os.path.exists(providers_file):
                with open(providers_file, 'r', encoding='utf-8') as f:
                    providers_data = json.load(f)
                    # 处理providers数据
                    if isinstance(providers_data, dict) and 'providers' in providers_data:
                        providers_section = providers_data['providers']
                        providers_response['metadata'] = providers_data.get('metadata', {})

                        # 转换索引格式为数组格式
                        if isinstance(providers_section, dict):
                            # 新的索引格式：providers是对象，以providerId为key
                            raw_providers = list(providers_section.values())
                        elif isinstance(providers_section, list):
                            # 旧的数组格式
                            raw_providers = providers_section
                        else:
                            raw_providers = []
                    elif isinstance(providers_data, list):
                        raw_providers = providers_data
                    else:
                        raw_providers = []

                    # 使用统一排序函数进行倒序排序
                    providers_response['providers'] = sort_providers_by_time(raw_providers, reverse=True)

                    logger.info(f"已读取并排序 {len(providers_response['providers'])} 个 Reclaim providers（按时间倒序）")

        except Exception as e:
            logger.warning(f"读取provider数据文件失败: {e}")
            providers_response['message'] = f"主流程执行成功，但读取provider数据失败: {str(e)}"

        logger.info(f"主流程同步执行完成，返回 {len(providers_response['providers'])} 个providers")

        # 添加真实识别到的mitm配置信息到响应中
        enhanced_response = {
            "mitm_host": mitm_host,  # 真实识别到的host
            "mitm_port": mitm_port,  # 真实识别到的port
            "providers": providers_response['providers'],
            "metadata": providers_response['metadata'],
            "message": providers_response['message']
        }

        return APIResponse(
            success=True,
            message=providers_response['message'],
            data=enhanced_response
        )
    else:
        # 执行失败
        error_msg = server_state.message if server_state.status == "error" else "执行未完成"
        logger.error(f"主流程执行失败: {error_msg}")
        raise HTTPException(
            status_code=500,
            detail=f"主流程执行失败: {error_msg}"
        )


class CreateTaskSessionRequest(BaseModel):
    providerId: str = Field(..., description="Provider唯一ID（唯一入参）")


class EditProviderRequest(BaseModel):
    """可编辑的关键字段（均为可选，提供哪个改哪个）"""
    loginUrl: Optional[str] = Field(default=None, description="登录页URL")
    institution: Optional[str] = Field(default=None, description="机构名")
    api_type: Optional[str] = Field(default=None, description="API类型")
    priority_level: Optional[str] = Field(default=None, description="优先级")
    value_score: Optional[float] = Field(default=None, description="价值评分")
    geoLocation: Optional[str] = Field(default=None, description="地理位置参数")
    injectionType: Optional[str] = Field(default=None, description="注入类型")
    pageTitle: Optional[str] = Field(default=None, description="页面标题")
    userAgent_ios: Optional[str] = Field(default=None, description="iOS UA 字符串")
    userAgent_android: Optional[str] = Field(default=None, description="Android UA 字符串")
    # 正则编辑：指定 requestData 下标与 responseMatches 下标，替换 value
    regex_request_index: Optional[int] = Field(default=None, ge=0, description="requestData 下标")
    regex_match_index: Optional[int] = Field(default=None, ge=0, description="responseMatches 下标")
    regex_value: Optional[str] = Field(default=None, description="新的正则表达式字符串")


def get_task_sessions_dir() -> str:
    """获取 task_sessions 存储目录（与仓库中 mitmproxy_addons/data/task_sessions 对齐）"""
    current_dir = Path(__file__).resolve().parent  # main-flow
    project_root = current_dir.parent  # mitmproxy2swagger
    sessions_dir = project_root / "mitmproxy_addons" / "data" / "task_sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    return str(sessions_dir)


def get_attestor_db_dir() -> str:
    """获取 attestor_db 存储目录（与插件数据目录对齐）"""
    current_dir = Path(__file__).resolve().parent  # main-flow
    project_root = current_dir.parent  # mitmproxy2swagger
    db_dir = project_root / "mitmproxy_addons" / "data" / "attestor_db"
    db_dir.mkdir(parents=True, exist_ok=True)
    return str(db_dir)


def _find_latest_providers_file() -> Optional[str]:
    data_dir = "data"
    if not os.path.exists(data_dir):
        return None
    provider_files = []
    for file in os.listdir(data_dir):
        if file.startswith("reclaim_providers_") and file.endswith(".json"):
            file_path = os.path.join(data_dir, file)
            provider_files.append((file_path, os.path.getmtime(file_path)))
    if not provider_files:
        return None
    latest_file = max(provider_files, key=lambda x: x[1])[0]
    return latest_file


def _edit_provider_fields(payload: EditProviderRequest, providers_doc: Dict[str, Any], provider_id: str) -> bool:
    """在 providers_doc 文档中编辑指定 provider 的关键字段
    返回是否有实际修改
    """
    providers_map = providers_doc.get("providers", {})
    if not isinstance(providers_map, dict):
        return False
    target = providers_map.get(provider_id)
    if not isinstance(target, dict):
        return False

    # providerIndex 同步
    provider_index = providers_doc.get("provider_index", {})
    index_entry = provider_index.get(provider_id) if isinstance(provider_index, dict) else None

    changed = False
    pc = target.get("providerConfig")
    if not isinstance(pc, dict):
        return False
    inner = pc.get("providerConfig")
    if not isinstance(inner, dict):
        return False

    # 1) loginUrl
    if payload.loginUrl is not None:
        if inner.get("loginUrl") != payload.loginUrl:
            inner["loginUrl"] = payload.loginUrl
            changed = True

    # 2) geoLocation
    if payload.geoLocation is not None:
        if inner.get("geoLocation") != payload.geoLocation:
            inner["geoLocation"] = payload.geoLocation
            changed = True

    # 3) injectionType
    if payload.injectionType is not None:
        if inner.get("injectionType") != payload.injectionType:
            inner["injectionType"] = payload.injectionType
            changed = True

    # 3.1) pageTitle
    if payload.pageTitle is not None:
        if inner.get("pageTitle") != payload.pageTitle:
            inner["pageTitle"] = payload.pageTitle
            changed = True

    # 3.2) userAgent
    if payload.userAgent_ios is not None or payload.userAgent_android is not None:
        ua = inner.get("userAgent")
        if not isinstance(ua, dict):
            ua = {"ios": None, "android": None}
        if payload.userAgent_ios is not None and ua.get("ios") != payload.userAgent_ios:
            ua["ios"] = payload.userAgent_ios
            changed = True
        if payload.userAgent_android is not None and ua.get("android") != payload.userAgent_android:
            ua["android"] = payload.userAgent_android
            changed = True
        inner["userAgent"] = ua

    # 4) metadata 同步 + provider_index 同步
    meta = inner.get("metadata")
    if not isinstance(meta, dict):
        meta = {}
        inner["metadata"] = meta

    def set_meta_field(field: str, value: Any):
        nonlocal changed
        if value is not None and meta.get(field) != value:
            meta[field] = value
            changed = True
        if isinstance(index_entry, dict) and value is not None and index_entry.get(field) != value:
            index_entry[field] = value
            changed = True

    set_meta_field("institution", payload.institution)
    set_meta_field("api_type", payload.api_type)
    set_meta_field("priority_level", payload.priority_level)
    if payload.value_score is not None:
        # 数值型
        set_meta_field("value_score", float(payload.value_score))

    # 5) regex 编辑
    if (
        payload.regex_value is not None and
        payload.regex_request_index is not None and
        payload.regex_match_index is not None
    ):
        try:
            reqs = inner.get("requestData")
            if isinstance(reqs, list) and 0 <= payload.regex_request_index < len(reqs):
                req = reqs[payload.regex_request_index]
                if isinstance(req, dict):
                    matches = req.get("responseMatches")
                    if isinstance(matches, list) and 0 <= payload.regex_match_index < len(matches):
                        m = matches[payload.regex_match_index]
                        if isinstance(m, dict):
                            if m.get("value") != payload.regex_value:
                                m["value"] = payload.regex_value
                                changed = True
        except Exception:
            # 忽略异常，保持幂等
            pass

    return changed


@app.post("/providers/{provider_id}/edit", response_model=APIResponse)
async def edit_provider(provider_id: str, payload: EditProviderRequest):
    """编辑指定 provider 的关键字段，并持久化到最新的 providers JSON 文件中"""
    latest = _find_latest_providers_file()
    if not latest or not os.path.exists(latest):
        raise HTTPException(status_code=404, detail="未找到Provider配置文件")

    try:
        with open(latest, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"读取配置失败: {e}")

    if not _edit_provider_fields(payload, doc, provider_id):
        return APIResponse(success=True, message="无字段更改或未找到指定Provider", data={"file_path": latest})

    # 备份原文件
    try:
        backup_path = latest + ".bak." + datetime.now().strftime("%Y%m%d%H%M%S")
        shutil.copyfile(latest, backup_path)
    except Exception:
        # 备份失败不阻断
        pass

    # 写回
    try:
        with open(latest, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"写回配置失败: {e}")

    return APIResponse(success=True, message="修改成功", data={"file_path": latest, "provider_id": provider_id})


@app.post("/task-sessions", response_model=APIResponse)
async def create_task_session(payload: CreateTaskSessionRequest):
    """新增一条 task_session 记录"""
    try:
        base_dir = get_task_sessions_dir()
        db = TaskSessionDB(base_dir=base_dir)

        # 在创建前，先检查同一 providerId 是否已存在 Pending 状态的 session
        try:
            latest_record = db.get_latest_pending_session_by_provider(payload.providerId, max_days_back=7)
            if latest_record:
                # 判断是否超过10分钟
                def _to_ts(val: Any) -> float:
                    try:
                        if isinstance(val, (int, float)):
                            return float(val)
                        dt = datetime.fromisoformat(str(val).replace('Z', '+00:00'))
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        return dt.timestamp()
                    except Exception:
                        return 0.0

                created_ts = _to_ts(latest_record.get("created_at") or latest_record.get("updated_at"))
                is_fresh = (time.time() - created_ts) <= 600  # 10分钟

                if is_fresh:
                    existing_session_id = latest_record.get("id")
                    return APIResponse(
                        success=True,
                        message="已存在Pending状态的session，返回最新记录",
                        data={
                            "session": latest_record,
                            "session_id": existing_session_id,
                            "base_dir": base_dir,
                            "reused": True
                        }
                    )
                # 否则继续创建新session；写入时DB会清理同日超过10分钟的Pending
        except Exception:
            # 预检失败不阻断创建流程
            pass

        session_id = db.create_session(
            task_id="",
            provider_id=payload.providerId,
            additional_data={
                # 与示例保持一致，提供 completed_at 字段
                "completed_at": time.time()
            }
        )

        if not session_id:
            raise HTTPException(status_code=500, detail="创建session失败")

        # 读取刚创建的记录返回
        record = db.get_session(session_id)

        return APIResponse(
            success=True,
            message="创建session成功",
            data={
                "session": record,
                "session_id": session_id,
                "base_dir": base_dir
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"创建task session失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"创建task session失败: {str(e)}")


@app.get("/task-sessions/{session_id}/response", response_model=APIResponse)
async def get_response_by_session(session_id: str):
    """根据 session_id 查询对应的 attestor 响应，优先返回 claim 对象；
    若无法获取claim，则返回session的必要信息。
    若 claim 中存在数组且元素为对象，则将对象压缩为单行字符串。
    """
    try:
        # 1) 读取 session 记录
        ts_db = TaskSessionDB(base_dir=get_task_sessions_dir())
        session_record = ts_db.get_session(session_id)
        if not session_record:
            raise HTTPException(status_code=404, detail="未找到对应的session记录")

        task_id = session_record.get("taskId") or session_record.get("task_id") or ""
        
        # 准备基础返回数据
        base_response_data = {
            "session_id": session_id,
            "status": session_record.get("status", "Unknown"),
            "taskId": task_id,
            "created_at": session_record.get("created_at"),
            "updated_at": session_record.get("updated_at"),
            "providerId": session_record.get("providerId"),
        }
        
        # 如果没有taskId，返回session基础信息
        if not task_id:
            # 添加attestor_params信息用于调试
            if "attestor_params" in session_record:
                base_response_data["attestor_params"] = session_record["attestor_params"]
            
            return APIResponse(
                success=True,
                message="该session没有taskId，返回session基础信息",
                data=base_response_data
            )

        # 2) 通过 taskId 从 attestor_db 获取响应
        attestor_db = AttestorDB(base_dir=get_attestor_db_dir())
        response_record = attestor_db.get_response(task_id)
        
        # 如果没有找到响应记录，返回session基础信息
        if not response_record:
            # 添加attestor_result信息（如果有的话）
            if "attestor_result" in session_record:
                base_response_data["attestor_result"] = session_record["attestor_result"]
            
            return APIResponse(
                success=True,
                message="未找到对应的响应记录，返回session基础信息",
                data=base_response_data
            )

        # 3) 尝试提取 claim 对象
        data_section = response_record.get("data") if isinstance(response_record, dict) else None
        claim_obj: Optional[Dict[str, Any]] = None

        if isinstance(data_section, dict):
            # 优先从 receipt.claim 提取
            receipt = data_section.get("receipt")
            if isinstance(receipt, dict) and isinstance(receipt.get("claim"), dict):
                claim_obj = receipt.get("claim")
            # 兼容直接存在的 claim 字段
            if claim_obj is None and isinstance(data_section.get("claim"), dict):
                claim_obj = data_section.get("claim")

        # 如果没有找到claim对象，返回session基础信息和响应信息
        if not isinstance(claim_obj, dict):
            base_response_data["response_data"] = response_record
            return APIResponse(
                success=True,
                message="响应中未找到claim对象，返回session和响应基础信息",
                data=base_response_data
            )

        # 4) 压缩 claim 中数组里的对象为单行字符串
        def compact_array_objects(value: Any) -> Any:
            if isinstance(value, list):
                compacted = []
                for item in value:
                    if isinstance(item, dict):
                        try:
                            compacted.append(json.dumps(item, ensure_ascii=False, separators=(",", ":")))
                        except Exception:
                            compacted.append(item)
                    else:
                        compacted.append(compact_array_objects(item))
                return compacted
            if isinstance(value, dict):
                return {k: compact_array_objects(v) for k, v in value.items()}
            return value

        compacted_claim = compact_array_objects(claim_obj)
        base_response_data["claim"] = compacted_claim

        return APIResponse(
            success=True,
            message="查询成功",
            data=base_response_data
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"查询响应失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"查询响应失败: {str(e)}")

@app.post("/upload-and-trigger")
async def upload_and_trigger(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    output_dir: str = "data"
):
    """上传mitm文件并触发主流程（离线模式）"""
    global server_state

    # 检查是否有任务正在运行
    if server_state.status == "running":
        raise HTTPException(
            status_code=400,
            detail="已有任务正在运行，请等待当前任务完成或重置状态"
        )

    # 验证文件类型
    if not file.filename.endswith('.mitm'):
        raise HTTPException(
            status_code=400,
            detail="只支持.mitm格式的文件"
        )

    try:
        # 保存上传的文件
        upload_dir = "uploads"
        os.makedirs(upload_dir, exist_ok=True)

        timestamp = int(time.time())
        safe_filename = f"upload_{timestamp}_{file.filename}"
        file_path = os.path.join(upload_dir, safe_filename)

        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)

        logger.info(f"文件上传成功: {file_path} ({len(content)} bytes)")

        # 构建配置
        config = {
            'output_dir': output_dir,
            'temp_dir': 'temp'
        }

        # 启动后台任务（离线模式）
        background_tasks.add_task(run_pipeline_async, config, True, file_path)

        return APIResponse(
            success=True,
            message=f"文件上传成功，主流程已触发（离线模式）",
            data={
                "task_id": server_state.current_task_id,
                "uploaded_file": file_path,
                "file_size": len(content),
                "config": config,
                "status": server_state.status
            }
        )

    except Exception as e:
        logger.error(f"文件上传失败: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"文件上传失败: {str(e)}"
        )


@app.get("/providers")
async def get_providers():
    """获取最新的Provider列表"""
    try:
        # 查找最新的reclaim_providers文件 (集成主流程生成的格式)
        data_dir = "data"
        if not os.path.exists(data_dir):
            return APIResponse(
                success=False,
                message="数据目录不存在，请先执行主流程",
                data={}
            )

        provider_files = []
        for file in os.listdir(data_dir):
            # 查找集成主流程生成的reclaim_providers文件
            if file.startswith("reclaim_providers_") and file.endswith(".json"):
                file_path = os.path.join(data_dir, file)
                provider_files.append((file_path, os.path.getmtime(file_path)))

        if not provider_files:
            return APIResponse(
                success=False,
                message="未找到Provider配置文件，请先执行主流程",
                data={}
            )

        # 获取最新的文件
        latest_file = max(provider_files, key=lambda x: x[1])[0]

        with open(latest_file, 'r', encoding='utf-8') as f:
            providers_data = json.load(f)

        # 提取providers数据和元数据
        providers_data_section = providers_data.get('providers', {})
        metadata = providers_data.get('metadata', {})

        # 转换索引格式为数组格式
        if isinstance(providers_data_section, dict):
            # 新的索引格式：providers是对象，以providerId为key
            providers_array = list(providers_data_section.values())
        elif isinstance(providers_data_section, list):
            # 旧的数组格式
            providers_array = providers_data_section
        else:
            providers_array = []

        # 使用统一排序函数进行倒序排序，最新的放在前面
        sorted_providers = sort_providers_by_time(providers_array, reverse=True)

        # 按域名映射替换 loginUrl（命中则替换为首页链接）
        domain_mapping = _load_domain_homepages()
        if isinstance(domain_mapping, dict) and domain_mapping:
            replaced_count = 0
            for prov in sorted_providers:
                current_login = _extract_login_url_from_provider(prov)
                new_home = _get_homepage_for_url(current_login or "", domain_mapping)
                if new_home and _set_login_url_in_provider(prov, new_home):
                    replaced_count += 1
            if replaced_count:
                logger.info(f"依据域名映射替换了 {replaced_count} 个 provider 的 loginUrl")

        return APIResponse(
            success=True,
            message=f"成功获取Provider列表（按时间倒序排序）",
            data={
                "providers": sorted_providers,
                "metadata": metadata,
                "file_path": latest_file,
                "providers_count": len(sorted_providers),
                "total_providers": metadata.get('total_providers', len(sorted_providers)),
                "last_modified": datetime.fromtimestamp(os.path.getmtime(latest_file)).isoformat()
            }
        )

    except Exception as e:
        logger.error(f"获取Provider列表失败: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"获取Provider列表失败: {str(e)}"
        )


@app.get("/files")
async def list_files():
    """列出所有输出文件"""
    try:
        files_info = []

        # 扫描data目录
        data_dir = "data"
        if os.path.exists(data_dir):
            for file in os.listdir(data_dir):
                if file.endswith('.json'):
                    file_path = os.path.join(data_dir, file)
                    stat = os.stat(file_path)
                    files_info.append({
                        "filename": file,
                        "path": file_path,
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "type": "output"
                    })

        # 扫描uploads目录
        uploads_dir = "uploads"
        if os.path.exists(uploads_dir):
            for file in os.listdir(uploads_dir):
                if file.endswith('.mitm'):
                    file_path = os.path.join(uploads_dir, file)
                    stat = os.stat(file_path)
                    files_info.append({
                        "filename": file,
                        "path": file_path,
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "type": "upload"
                    })

        # 按修改时间排序
        files_info.sort(key=lambda x: x['modified'], reverse=True)

        return APIResponse(
            success=True,
            message=f"找到 {len(files_info)} 个文件",
            data={
                "files": files_info,
                "total_count": len(files_info)
            }
        )

    except Exception as e:
        logger.error(f"列出文件失败: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"列出文件失败: {str(e)}"
        )


@app.get("/download/{file_type}/{filename}")
async def download_file(file_type: str, filename: str):
    """下载文件"""
    try:
        # 验证文件类型
        if file_type == "output":
            base_dir = "data"
        elif file_type == "upload":
            base_dir = "uploads"
        else:
            raise HTTPException(status_code=400, detail="无效的文件类型")

        file_path = os.path.join(base_dir, filename)

        # 验证文件存在且在允许的目录内
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="文件不存在")

        # 安全检查：确保文件在指定目录内
        if not os.path.abspath(file_path).startswith(os.path.abspath(base_dir)):
            raise HTTPException(status_code=403, detail="访问被拒绝")

        return FileResponse(
            path=file_path,
            filename=filename,
            media_type='application/octet-stream'
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"下载文件失败: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"下载文件失败: {str(e)}"
        )


def main():
    """启动API服务器"""
    # 从环境变量获取配置，如果没有则使用默认值
    host = os.getenv("API_SERVER_HOST", "0.0.0.0")
    port = int(os.getenv("API_SERVER_PORT", "8000"))
    local_ip = os.getenv("API_SERVER_LOCAL_IP") or get_local_ip()

    print("🚀 启动银行Provider生成API服务器")
    print("=" * 70)
    print(f"📍 本机IP地址: {local_ip}")
    print(f"🌐 绑定地址: {host}:{port}")
    print(f"🔗 访问地址: http://{local_ip}:{port}")
    print(f"📖 API文档: http://{local_ip}:{port}/docs")
    print(f"🔍 健康检查: http://{local_ip}:{port}/health")
    print(f"🧪 测试界面: 打开 api_test_client.html")
    print("=" * 70)
    print("💡 这是一个独立的API服务，不依赖mitmproxy插件")

    # 显示网络配置信息
    if host == "0.0.0.0":
        print("🌐 监听所有网络接口 (可通过本机IP和localhost访问)")
    elif host == local_ip:
        print("🏠 仅监听本机IP (不可通过localhost访问)")
    elif host == "127.0.0.1":
        print("🔒 仅监听localhost (仅本机可访问)")
    else:
        print(f"🎯 监听指定地址: {host}")

    print("🛑 按 Ctrl+C 停止服务")
    print()

    # 启动服务器
    try:
        uvicorn.run(
            "independent_api_server:app",
            host=host,
            port=port,
            reload=False,
            log_level="info"
        )
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"❌ 端口 {port} 已被占用")
            print(f"💡 请使用其他端口或停止占用该端口的进程")
            print(f"💡 查看占用进程: lsof -i :{port}")
        else:
            print(f"❌ 启动服务器失败: {e}")
        exit(1)
    except KeyboardInterrupt:
        print("\n🛑 服务器已停止")
    except Exception as e:
        print(f"❌ 服务器异常: {e}")
        exit(1)


if __name__ == "__main__":
    main()