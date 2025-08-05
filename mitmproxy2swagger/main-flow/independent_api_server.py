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

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from http import HTTPStatus
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn

# 导入主流程相关模块
from integrated_main_pipeline import IntegratedMainPipeline
from dynamic_config import dynamic_config



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
    def get_provider_timestamp(provider):
        try:
            # 从metadata中获取生成时间
            generated_at = provider.get('providerConfig', {}).get('providerConfig', {}).get('metadata', {}).get('generated_at', '')
            if generated_at:
                # 解析ISO格式时间戳
                from datetime import datetime
                return datetime.fromisoformat(generated_at.replace('Z', '+00:00'))
            else:
                # 如果没有时间戳，使用当前时间
                return datetime.now()
        except:
            # 解析失败时使用当前时间
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
            "files": "/files"
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
                    # 直接返回providers列表
                    if isinstance(providers_data, dict) and 'providers' in providers_data:
                        raw_providers = providers_data['providers']
                        providers_response['metadata'] = providers_data.get('metadata', {})
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

        # 提取providers数组和元数据
        providers_array = providers_data.get('providers', [])
        metadata = providers_data.get('metadata', {})

        # 使用统一排序函数进行倒序排序，最新的放在前面
        sorted_providers = sort_providers_by_time(providers_array, reverse=True)

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
    # 动态获取本机IP
    local_ip = get_local_ip()
    port = 8000

    print("🚀 启动银行Provider生成API服务器")
    print("=" * 70)
    print(f"📍 本机IP地址: {local_ip}")
    print(f"🌐 服务地址: http://{local_ip}:{port}")
    print(f"📖 API文档: http://{local_ip}:{port}/docs")
    print(f"🔍 健康检查: http://{local_ip}:{port}/health")
    print(f"🧪 测试界面: 打开 api_test_client.html")
    print("=" * 70)
    print("💡 这是一个独立的API服务，不依赖mitmproxy插件")
    print("🛑 按 Ctrl+C 停止服务")
    print()

    # 启动服务器，监听所有接口
    uvicorn.run(
        "independent_api_server:app",
        host="0.0.0.0",
        port=port,
        reload=False,
        log_level="info"
    )


if __name__ == "__main__":
    main()