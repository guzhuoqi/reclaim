#!/usr/bin/env python3
"""
Attestor集成转发Addon
Attestor Integration Forwarding Addon for mitmproxy

功能特性：
1. 智能请求识别 - 识别需要通过attestor处理的API请求
2. 参数转换 - 将HTTP请求转换为attestor调用参数
3. 异步执行 - 异步调用attestor node生成ZK proof
4. 响应处理 - 处理attestor返回结果并生成响应
5. 错误处理 - 完善的错误处理和降级机制

使用方式：
    mitmproxy -s attestor_forwarding_addon.py
    mitmweb -s attestor_forwarding_addon.py
"""

import asyncio
import json
import logging
import os
import subprocess
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse, parse_qs
import threading
import queue
from attestor_db import get_attestor_db
import requests

# 可选依赖
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from mitmproxy import http, ctx
from mitmproxy.addonmanager import Loader

# 导入我们的转换器
try:
    from http_to_attestor_converter import HttpToAttestorConverter
except ImportError:
    print("❌ 无法导入 HttpToAttestorConverter，请确保文件在同一目录下")
    raise

# 导入新的session-based匹配器
try:
    from session_based_matcher import get_session_matcher
except ImportError:
    print("❌ 无法导入 SessionBasedMatcher，请确保文件在同一目录下")
    raise


class AttestorExecutor:
    """Attestor API执行器"""

    def __init__(self, api_host: str = "localhost", api_port: int = 3000, max_workers: int = 3,
                 use_zkme_express: bool = False, zkme_base_url: str = "https://test-exp.bitkinetic.com",
                 queue_size: Optional[int] = None,
                 use_wss_attestor: bool = False, wss_attestor_url: Optional[str] = None, request_timeout: int = 180,
                 attestor_host_port: Optional[str] = None):
        self.api_host = api_host
        self.api_port = api_port
        self.max_workers = max_workers
        self.use_zkme_express = use_zkme_express
        self.zkme_base_url = zkme_base_url
        self.use_wss_attestor = use_wss_attestor
        self.wss_attestor_url = wss_attestor_url
        self.request_timeout = request_timeout
        # 新增：本地脚本模式下的远端 attestor 地址（host:port 或 "local"）
        self.attestor_host_port = attestor_host_port or "local"
        # 可配置队列大小，与worker数量解耦
        self.executor_queue = queue.Queue(maxsize=(queue_size if isinstance(queue_size, int) and queue_size > 0 else max_workers))
        self.active_tasks = {}
        self.task_counter = 0

        # 初始化数据库
        self.db = get_attestor_db()
        print(f"📊 Attestor 数据库已初始化: {self.db.base_dir}")

        # 初始化zkme-express客户端（如果需要）
        if self.use_zkme_express:
            try:
                # 尝试相对导入
                from .zkme_express_client import ZkmeExpressClient
            except ImportError:
                # 如果相对导入失败，尝试绝对导入
                import sys
                import os
                current_dir = os.path.dirname(os.path.abspath(__file__))
                if current_dir not in sys.path:
                    sys.path.insert(0, current_dir)
                from zkme_express_client import ZkmeExpressClient

            self.zkme_client = ZkmeExpressClient(self.zkme_base_url)
            print(f"🌐 启用zkme-express模式: {self.zkme_base_url}")

        # 初始化 WSS 客户端（如果需要）
        if self.use_wss_attestor:
            try:
                import websocket  # websocket-client
            except Exception:
                print("⚠️ 未安装 websocket-client，WSS attestor 模式可能不可用。请执行: pip install websocket-client")

        # 初始化工作线程
        for i in range(max_workers):
            worker = threading.Thread(target=self._worker_thread, daemon=True)
            worker.start()

    def _worker_thread(self):
        """工作线程"""
        while True:
            try:
                task = self.executor_queue.get(timeout=1)
                if task is None:  # 停止信号
                    self.executor_queue.task_done()
                    break
                self._execute_task(task)
                self.executor_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"❌ Worker thread error: {e}")
                self.executor_queue.task_done()

    def _execute_task(self, task: Dict[str, Any]):
        """执行attestor任务 - 支持zkme-express API或本地Node.js"""
        task_id = task["task_id"]
        attestor_params = task["attestor_params"]
        callback = task["callback"]

        # 保存请求到数据库
        request_data = {
            "task_id": task_id,
            "url": attestor_params["params"].get("url"),
            "method": attestor_params["params"].get("method"),
            "attestor_params": attestor_params
        }
        self.db.save_request(task_id, request_data)

        # 根据配置选择执行方式
        if self.use_wss_attestor and self.wss_attestor_url:
            # 优先本地Node wrapper，以复用 attestor-core 的完整协议栈
            self._execute_via_wss_node_wrapper(task_id, attestor_params, callback)
        elif self.use_zkme_express:
            self._execute_via_zkme_express(task_id, attestor_params, callback)
        else:
            self._execute_via_local_script(task_id, attestor_params, callback)

    def _execute_via_wss_node_wrapper(self, task_id: str, attestor_params: Dict[str, Any], callback):
        """通过本地 Node 脚本调 WSS（使用 attestor-core createClaimOnAttestor）"""
        try:
            start_time = time.time()
            import shlex, subprocess, os
            script_path = os.path.join(os.path.dirname(__file__), 'call-attestor-wss.js')
            params_json = json.dumps(attestor_params.get('params', {}))
            secret_params_json = json.dumps(attestor_params.get('secretParams', {}))
            client_url = self.wss_attestor_url

            cmd = f"node {shlex.quote(script_path)} --params {shlex.quote(params_json)} --secretParams {shlex.quote(secret_params_json)} --clientUrl {shlex.quote(client_url)}"
            env = dict(os.environ)
            env['PRIVATE_KEY'] = env.get('PRIVATE_KEY') or '0x0123788edad59d7c013cdc85e4372f350f828e2cec62d9a2de4560e69aec7f89'
            # 抑制 Node 的非致命警告，避免污染 stdout 导致 JSON 解析失败
            env['NODE_NO_WARNINGS'] = env.get('NODE_NO_WARNINGS') or '1'
            env['NODE_OPTIONS'] = (env.get('NODE_OPTIONS') + ' --no-warnings') if env.get('NODE_OPTIONS') else '--no-warnings'

            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=self.request_timeout, env=env)
            execution_time = time.time() - start_time

            def _try_parse_json_from_stdout(stdout_str: str) -> Optional[Dict[str, Any]]:
                # 直接解析
                try:
                    return json.loads(stdout_str)
                except Exception:
                    pass
                # 提取第一个花括号 JSON 块
                try:
                    import re
                    m = re.search(r"\{[\s\S]*\}", stdout_str)
                    if m:
                        return json.loads(m.group(0))
                except Exception:
                    pass
                # 提取最后一行尝试解析
                try:
                    last_line = stdout_str.strip().splitlines()[-1]
                    return json.loads(last_line)
                except Exception:
                    return None

            if result.returncode == 0 and result.stdout:
                parsed = _try_parse_json_from_stdout(result.stdout)
                if parsed is not None:
                    payload = parsed
                else:
                    payload = { 'success': False, 'error': 'Invalid JSON from node wrapper', 'stdout': result.stdout[-800:] }
            else:
                payload = { 'success': False, 'error': result.stderr or 'node wrapper failed', 'stdout': result.stdout[-500:] }

            # 统一保存
            save_obj = {
                'success': bool(payload.get('success')),
                'task_id': task_id,
                'execution_time': execution_time
            }
            if payload.get('success'):
                save_obj['receipt'] = payload.get('receipt')
            else:
                save_obj['error'] = payload.get('error')
                if 'stdout' in payload:
                    save_obj['stdout'] = payload.get('stdout')

            self.db.save_response(task_id, save_obj, execution_time)
            callback(save_obj)
        except Exception as e:
            callback({ 'success': False, 'error': str(e), 'task_id': task_id })

    def _execute_via_wss(self, task_id: str, attestor_params: Dict[str, Any], callback):
        """通过 WSS attestor 执行"""
        try:
            import websocket
            import json as _json
            import time as _time
            import ssl as _ssl

            start_time = time.time()
            print(f"🚀 开始执行Attestor任务 {task_id} (通过WSS: {self.wss_attestor_url})...")

            # 构造握手参数
            header_list = []
            if getattr(self, 'wss_headers', None):
                for k, v in (self.wss_headers or {}).items():
                    header_list.append(f"{k}: {v}")
            origin = getattr(self, 'wss_origin', None)
            sslopt = None
            if getattr(self, 'wss_ssl_insecure', False):
                sslopt = {"cert_reqs": _ssl.CERT_NONE, "check_hostname": False}

            timeout = getattr(self, 'wss_connect_timeout', None) or self.request_timeout

            # 可选 trace
            if getattr(self, 'wss_enable_trace', False):
                websocket.enableTrace(True)

            ws = websocket.create_connection(
                self.wss_attestor_url,
                timeout=timeout,
                header=header_list if header_list else None,
                origin=origin,
                sslopt=sslopt
            )
            try:
                payload = {
                    "type": "generate_receipt",
                    "taskId": task_id,
                    "params": attestor_params.get("params", {}),
                    "secretParams": attestor_params.get("secretParams", {}),
                }
                ws.send(_json.dumps(payload))

                # 简单等待单条响应
                raw_msg = ws.recv()
                execution_time = time.time() - start_time
                try:
                    msg = _json.loads(raw_msg)
                except Exception:
                    msg = {"success": False, "error": "Invalid JSON from WSS", "raw": raw_msg}

                if msg.get("success"):
                    response_data = {
                        "success": True,
                        "receipt": msg.get("receipt"),
                        "task_id": task_id,
                        "execution_time": execution_time,
                        "timestamp": msg.get("timestamp")
                    }
                    self.db.save_response(task_id, response_data, execution_time)
                else:
                    response_data = {
                        "success": False,
                        "error": msg.get("error", "WSS attestor error"),
                        "task_id": task_id,
                        "execution_time": execution_time
                    }
                    self.db.save_response(task_id, response_data, execution_time)

                callback(response_data)
            finally:
                try:
                    ws.close()
                except Exception:
                    pass
        except Exception as e:
            print(f"❌ WSS attestor执行失败: {e}")
            callback({
                "success": False,
                "error": str(e),
                "task_id": task_id
            })

    def _execute_via_zkme_express(self, task_id: str, attestor_params: Dict[str, Any], callback):
        """通过zkme-express API执行"""
        try:
            print(f"🚀 开始执行Attestor任务 {task_id} (通过zkme-express API)...")

            # 使用asyncio运行异步方法
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            try:
                result = loop.run_until_complete(
                    self.zkme_client.execute_attestor_task(task_id, attestor_params)
                )
                callback(result)
            finally:
                loop.close()

        except Exception as e:
            print(f"❌ zkme-express执行失败: {e}")
            callback({
                "success": False,
                "error": str(e),
                "task_id": task_id
            })

    def _execute_via_local_script(self, task_id: str, attestor_params: Dict[str, Any], callback):
        """通过本地Node.js脚本执行（原有逻辑）"""

        try:
            start_time = time.time()
            print(f"🚀 开始执行Attestor任务 {task_id} (通过子进程调用Node.js)...")
            print(f"💾 请求已保存到数据库")
            print(f"⏰ 开始时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))}")

            # 构建命令行参数 - 使用编译后的 JavaScript 文件
            attestor_script = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                "attestor-core/lib/scripts/generate-receipt-for-python.js"
            )

            # 准备参数
            params_json = json.dumps(attestor_params["params"])
            secret_params_json = json.dumps(attestor_params.get("secretParams", {}))

            # 🔍 调试：打印实际传递的参数
            print(f"🔍 调试 - 传递给attestor的完整参数:")
            print(f"   任务ID: {task_id}")
            print(f"   脚本路径: {attestor_script}")
            print(f"   脚本存在: {os.path.exists(attestor_script)}")
            print(f"   params (完整): {params_json}")
            print(f"   secretParams (完整): {secret_params_json}")

            # 解析并分析secretParams内容
            try:
                secret_params_obj = json.loads(secret_params_json)
                print(f"   secretParams keys: {list(secret_params_obj.keys())}")
                if 'headers' in secret_params_obj:
                    print(f"   ❌ 警告: secretParams中仍包含headers字段: {secret_params_obj['headers']}")
                else:
                    print(f"   ✅ secretParams中不包含headers字段，符合预期")
            except:
                print(f"   ❌ secretParams JSON解析失败")

            # 使用 shell 重定向将调试输出重定向到 /dev/null
            import shlex
            attestor_host_port = getattr(self, 'attestor_host_port', 'local')
            print(f"   attestor_host_port: {attestor_host_port}")

            # 若 attestor_host_port 为完整 ws(s):// URL，走 WSS 包装脚本，避免强制 ws://
            if isinstance(attestor_host_port, str) and (attestor_host_port.startswith('wss://') or attestor_host_port.startswith('ws://')):
                wrapper_js = os.path.join(os.path.dirname(__file__), 'call-attestor-wss.js')
                client_url = attestor_host_port
                cmd_str = (
                    f"cd {shlex.quote(os.path.dirname(os.path.dirname(attestor_script)))} && "
                    f"node {shlex.quote(wrapper_js)} --params {shlex.quote(params_json)} "
                    f"--secretParams {shlex.quote(secret_params_json)} --clientUrl {shlex.quote(client_url)} 2>/dev/null"
                )
            else:
                # host:port 或 'local'，使用 generate-receipt-for-python.js
                fixed_workdir = "/opt/reclaim/attestor-core/lib"
                # 直接用相对路径 scripts/generate-receipt-for-python.js，防止路径重复
                cmd_str = (
                    f"cd {fixed_workdir} && "
                    f"node scripts/generate-receipt-for-python.js --params {shlex.quote(params_json)} "
                    f"--secretParams {shlex.quote(secret_params_json)} --attestor {shlex.quote(attestor_host_port)}"
                )

            print(f"   执行命令: node generate-receipt-for-python.js [参数已隐藏]")
            print(f"   工作目录: /opt/reclaim/attestor-core/lib")  # 固定绝对路径
            print(f"   attestor_host_port: {attestor_host_port}")

            # 设置环境变量
            env = dict(os.environ)
            env['PRIVATE_KEY'] = '0x0123788edad59d7c013cdc85e4372f350f828e2cec62d9a2de4560e69aec7f89'
            env['NODE_ENV'] = 'development'
            # 抑制 Node 的非致命警告，避免污染 stdout
            env['NODE_NO_WARNINGS'] = env.get('NODE_NO_WARNINGS') or '1'
            env['NODE_OPTIONS'] = (env.get('NODE_OPTIONS') + ' --no-warnings') if env.get('NODE_OPTIONS') else '--no-warnings'

            # 使用 Popen + communicate() 来避免 65536 字节缓冲区限制
            print(f"   使用 Popen + communicate() 避免输出截断...")

            try:
                print(f"   🔄 启动子进程...")
                process = subprocess.Popen(
                    cmd_str,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=env
                )
                print(f"   📋 进程 PID: {process.pid}")

                # 监控进程状态（如果 psutil 可用）
                if HAS_PSUTIL:
                    def monitor_process():
                        try:
                            proc = psutil.Process(process.pid)
                            while proc.is_running():
                                memory_mb = proc.memory_info().rss / 1024 / 1024
                                cpu_percent = proc.cpu_percent()
                                print(f"   📊 进程监控 PID={process.pid}: 内存={memory_mb:.1f}MB, CPU={cpu_percent:.1f}%")
                                time.sleep(10)  # 每10秒监控一次
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                        except Exception as e:
                            print(f"   ⚠️ 进程监控异常: {e}")

                    monitor_thread = threading.Thread(target=monitor_process, daemon=True)
                    monitor_thread.start()
                else:
                    print(f"   ⚠️ psutil 不可用，跳过进程监控")

                # 使用 communicate() 获取完整输出，无大小限制
                print(f"   ⏳ 等待进程完成 (超时: 180秒)...")
                stdout, stderr = process.communicate(timeout=180)

                # 创建兼容的 result 对象
                class PopenResult:
                    def __init__(self, returncode, stdout, stderr):
                        self.returncode = returncode
                        self.stdout = stdout
                        self.stderr = stderr

                result = PopenResult(process.returncode, stdout, stderr)
                print(f"   ✅ 进程完成: 返回码={process.returncode}, stdout={len(stdout)} 字符, stderr={len(stderr)} 字符")

            except subprocess.TimeoutExpired:
                print(f"   ⏰ 进程超时，强制终止 PID={process.pid}")
                process.kill()
                stdout, stderr = process.communicate()
                result = PopenResult(process.returncode, stdout, stderr)
                print(f"   💀 进程已终止: stdout={len(stdout)} 字符, stderr={len(stderr)} 字符")
                raise subprocess.TimeoutExpired(cmd_str, 180)

            execution_time = time.time() - start_time

            print(f"   进程返回码: {result.returncode}")
            print(f"   执行时间: {execution_time:.2f}秒")
            print(f"   stdout长度: {len(result.stdout) if result.stdout else 0}")
            print(f"   stderr长度: {len(result.stderr) if result.stderr else 0}")

            def _try_parse_json_from_stdout(stdout_str: str):
                # 先尝试直接解析
                try:
                    return json.loads(stdout_str)
                except Exception:
                    pass
                # 提取第一个 JSON 对象
                try:
                    import re
                    m = re.search(r"\{[\s\S]*\}", stdout_str)
                    if m:
                        return json.loads(m.group(0))
                except Exception:
                    pass
                # 尝试最后一行
                try:
                    return json.loads(stdout_str.strip().splitlines()[-1])
                except Exception:
                    return None

            if result.returncode == 0 and result.stdout:
                # 解析 JSON 输出（容错）
                attestor_response = _try_parse_json_from_stdout(result.stdout)
                if attestor_response is not None:
                    print(f"   解析JSON成功: {attestor_response.get('success', False)}")

                    if attestor_response.get("success"):
                        # 成功情况
                        response_data = {
                            "success": True,
                            "receipt": attestor_response.get("receipt"),
                            "task_id": task_id,
                            "execution_time": execution_time,
                            "timestamp": attestor_response.get("timestamp")
                        }

                        # 提取 extractedParameters
                        receipt = attestor_response.get("receipt", {})
                        if receipt.get("claim") and receipt["claim"].get("context"):
                            try:
                                context = json.loads(receipt["claim"]["context"])
                                if context.get("extractedParameters"):
                                    response_data["extractedParameters"] = context["extractedParameters"]
                                    print(f"   提取的参数: {context['extractedParameters']}")
                            except Exception as parse_error:
                                print(f"   解析context失败: {parse_error}")

                        print(f"✅ Attestor任务 {task_id} 执行成功 (耗时: {execution_time:.2f}秒)")

                        # 保存成功响应到数据库
                        self.db.save_response(task_id, response_data, execution_time)
                        print(f"💾 成功响应已保存到数据库")

                    else:
                        # Attestor 返回错误
                        response_data = {
                            "success": False,
                            "error": attestor_response.get("error", "Unknown attestor error"),
                            "task_id": task_id,
                            "execution_time": execution_time
                        }
                        print(f"❌ Attestor任务 {task_id} 返回错误: {attestor_response.get('error')}")

                        # 保存错误响应到数据库
                        self.db.save_response(task_id, response_data, execution_time)
                        print(f"💾 错误响应已保存到数据库")

                else:
                    # JSON 解析失败
                    response_data = {
                        "success": False,
                        "error": "JSON parse error",
                        "raw_stdout": result.stdout[:800],  # 只保留前800字符
                        "task_id": task_id,
                        "execution_time": execution_time
                    }
                    print(f"❌ Attestor任务 {task_id} JSON解析失败")
                    print(f"   原始输出: {result.stdout[:200]}...")

                    # 保存JSON解析错误到数据库
                    self.db.save_response(task_id, response_data, execution_time)
                    print(f"💾 JSON解析错误已保存到数据库")

            else:
                # 进程执行失败
                response_data = {
                    "success": False,
                    "error": f"Process failed with code {result.returncode}",
                    "stderr": result.stderr,
                    "stdout": result.stdout,
                    "task_id": task_id,
                    "execution_time": execution_time
                }
                print(f"❌ Attestor任务 {task_id} 进程执行失败 (返回码: {result.returncode})")
                if result.stderr:
                    print(f"   错误输出: {result.stderr}")

                # 保存进程执行失败到数据库
                self.db.save_response(task_id, response_data, execution_time)
                print(f"💾 进程执行失败已保存到数据库")

        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            response_data = {
                "success": False,
                "error": "Process timeout",
                "task_id": task_id,
                "execution_time": execution_time
            }
            print(f"⏰ Attestor任务 {task_id} 进程超时")

            # 保存超时错误到数据库
            self.db.save_response(task_id, response_data, execution_time)
            print(f"💾 超时错误已保存到数据库")

        except Exception as e:
            execution_time = time.time() - start_time
            response_data = {
                "success": False,
                "error": str(e),
                "task_id": task_id,
                "execution_time": execution_time
            }
            print(f"❌ Attestor任务 {task_id} 执行异常: {e}")

            # 保存异常错误到数据库
            self.db.save_response(task_id, response_data, execution_time)
            print(f"💾 异常错误已保存到数据库")

        # 调用回调
        callback(response_data)

    def submit_task(self, attestor_params: Dict[str, Any], callback) -> str:
        """提交attestor任务"""
        self.task_counter += 1
        task_id = f"task_{self.task_counter}_{int(time.time())}"

        task = {
            "task_id": task_id,
            "attestor_params": attestor_params,
            "callback": callback,
            "submitted_at": time.time()
        }

        self.active_tasks[task_id] = task

        try:
            print(f"📝 提交Attestor任务 {task_id} 到队列（当前队列大小: {self.executor_queue.qsize()}）")
            self.executor_queue.put(task, timeout=5)  # 增加超时时间
            print(f"✅ Attestor任务 {task_id} 已成功提交到队列")
            return task_id
        except queue.Full:
            del self.active_tasks[task_id]
            print(f"❌ 队列已满，无法提交任务 {task_id}")
            raise Exception("Attestor executor queue is full")


class AttestorForwardingAddon:
    """Attestor集成转发Addon主类"""

    def __init__(self):
        self.config: Dict[str, Any] = {}
        self.logger: Optional[logging.Logger] = None
        self.converter = HttpToAttestorConverter()
        self.executor: Optional[AttestorExecutor] = None
        self.pending_responses: Dict[str, http.HTTPFlow] = {}
        self.metrics: Dict[str, Any] = defaultdict(int)

        # 连接绑定: client_conn.id -> { session_id, bound_at, ttl, peername }
        self.connection_bindings: Dict[str, Dict[str, Any]] = {}
        # 绑定域名与路径（最小可落地实现）
        self.binding_host: str = "bind.reclaim.local"
        self.binding_path: str = "/bind"
        self.binding_ttl_seconds: int = 15 * 60

        # 初始化session-based匹配器
        self.session_matcher = get_session_matcher()
        print("✅ AttestorForwardingAddon 已集成 SessionBasedMatcher")

        # 加载配置
        self._load_config()
        self._setup_logging()
        self._setup_executor()

        # 启动清理线程
        self._start_cleanup_thread()

    def _start_cleanup_thread(self):
        """启动定期清理线程"""
        def cleanup_worker():
            while True:
                try:
                    time.sleep(30)  # 每30秒检查一次
                    current_time = time.time()

                    # 清理超过5分钟的pending responses
                    expired_tasks = []
                    for task_id, flow in self.pending_responses.items():
                        # 假设任务ID包含时间戳
                        try:
                            task_timestamp = int(task_id.split('_')[-1])
                            if current_time - task_timestamp > 300:  # 5分钟
                                expired_tasks.append(task_id)
                        except:
                            # 如果解析时间戳失败，也清理掉
                            if len(expired_tasks) < 10:  # 限制一次清理的数量
                                expired_tasks.append(task_id)

                    for task_id in expired_tasks:
                        print(f"🧹 清理过期任务: {task_id}")
                        del self.pending_responses[task_id]

                    # 清理过期的连接绑定
                    expired_conn_ids: List[str] = []
                    for conn_id, bind in self.connection_bindings.items():
                        bound_at = bind.get("bound_at", 0)
                        ttl = bind.get("ttl", self.binding_ttl_seconds)
                        if current_time - bound_at > ttl:
                            expired_conn_ids.append(conn_id)
                    for conn_id in expired_conn_ids:
                        info = self.connection_bindings.pop(conn_id, None)
                        if info:
                            print(f"🧹 清理过期连接绑定: conn_id={conn_id}, session_id={info.get('session_id')}")

                except Exception as e:
                    print(f"❌ 清理线程异常: {e}")

        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        cleanup_thread.start()

    def _load_config(self):
        """加载配置文件"""
        config_path = Path(__file__).parent / "attestor_forwarding_config.json"
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
            print(f"✅ 加载Attestor转发配置: {config_path}")
        except Exception as e:
            print(f"❌ 加载配置文件失败: {e}")
            # 使用默认配置
            self.config = self._get_default_config()

    def _get_default_config(self) -> Dict[str, Any]:
        """获取默认配置"""
        return {
            "global_settings": {
                "enable_logging": True,
                "log_level": "INFO",
                "attestor_core_path": "../attestor-core",
                "max_workers": 3,
                "queue_size": 10,
                "request_timeout": 180,
                # 执行模式：blocking_ack（202 返回）/ non_blocking（直通上游，推荐默认）
                "execution_mode": "blocking_ack",
                # 是否在请求与响应上附带任务ID头，便于链路追踪
                "add_task_id_header": False
            },
            "attestor_rules": {
                "enabled": True,
                "rules": [
                    {
                        "name": "银行余额查询",
                        "domains": ["*.cmbwinglungbank.com"],
                        "paths": ["/ibanking/.*"],
                        "methods": ["POST", "GET"],
                        "response_patterns": {
                            "hkd_balance": r"HKD[^\\d]*(\\d[\\d,]*\\.\\d{2})",
                            "usd_balance": r"USD[^\\d]*(\\d[\\d,]*\\.\\d{2})"
                        },
                        "geo_location": "HK"
                    }
                ]
            },
            "response_settings": {
                "include_original_response": True,
                "include_attestor_proof": True,
                "response_format": "json"
            }
        }

    def _setup_logging(self):
        """设置日志"""
        if not self.config.get("global_settings", {}).get("enable_logging", True):
            return

        log_level = self.config.get("global_settings", {}).get("log_level", "INFO")
        log_file = "logs/attestor_forwarding.log"

        # 确保日志目录存在
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)

        self.logger = logging.getLogger("AttestorForwardingAddon")
        self.logger.setLevel(getattr(logging, log_level))

        # 文件处理器
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(getattr(logging, log_level))

        # 格式化器
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)

        self.logger.addHandler(file_handler)
        self.logger.info("AttestorForwardingAddon 初始化完成")

    def _setup_executor(self):
        """设置执行器"""
        max_workers = self.config.get("global_settings", {}).get("max_workers", 3)
        queue_size = self.config.get("global_settings", {}).get("queue_size", None)
        api_host = self.config.get("global_settings", {}).get("zkme_express_host", "localhost")
        api_port = self.config.get("global_settings", {}).get("zkme_express_port", 3000)
        use_zkme_express = self.config.get("global_settings", {}).get("use_zkme_express", False)
        zkme_base_url = self.config.get("global_settings", {}).get("zkme_base_url", "https://test-exp.bitkinetic.com")
        use_wss_attestor = self.config.get("global_settings", {}).get("use_wss_attestor", False)
        wss_attestor_url = self.config.get("global_settings", {}).get("wss_attestor_url", None)
        request_timeout = self.config.get("global_settings", {}).get("request_timeout", 180)

        try:
            self.executor = AttestorExecutor(
                api_host=api_host,
                api_port=api_port,
                max_workers=max_workers,
                use_zkme_express=use_zkme_express,
                zkme_base_url=zkme_base_url,
                queue_size=queue_size,
                use_wss_attestor=use_wss_attestor,
                wss_attestor_url=wss_attestor_url,
                request_timeout=request_timeout,
                attestor_host_port=self.config.get("global_settings", {}).get("attestor_host_port", "local")
            )
            if use_wss_attestor and wss_attestor_url:
                mode = f"wss({wss_attestor_url})"
            else:
                mode = "zkme-express" if use_zkme_express else "local-script"
            print(f"✅ Attestor执行器初始化完成: {mode} 模式")
        except Exception as e:
            print(f"❌ Attestor执行器初始化失败: {e}")

    def load(self, loader: Loader):
        """mitmproxy加载时调用"""
        loader.add_option(
            name="attestor_enabled",
            typespec=bool,
            default=True,
            help="是否启用Attestor转发功能"
        )

        loader.add_option(
            name="attestor_config",
            typespec=str,
            default="",
            help="Attestor转发配置文件路径"
        )

    def request(self, flow: http.HTTPFlow) -> None:
        """处理HTTP请求"""
        if not ctx.options.attestor_enabled:
            return

        # 更新指标
        self.metrics["total_requests"] += 1

        # 先处理绑定请求（最小可落地）
        if self._maybe_handle_binding_request(flow):
            # 已处理（返回204或错误提示），不再继续后续逻辑
            return

        # 如果当前连接已绑定，打印命中日志并附着 session 元数据（优先按session直连）
        self._maybe_log_binding_hit(flow)
        self._attach_session_metadata(flow)

        # 🎯 第一个功能点：检查pending sessions并尝试匹配
        session_match = self.session_matcher.check_pending_sessions_and_match(flow)

        if session_match:
            # 统一路由日志（有 session 的情况）
            sid = session_match.get('session', {}).get('id') or flow.metadata.get('session_id')
            pid = session_match.get('provider_id')
            route_msg = f"路由选择: Session直连 | session_id={sid} | provider_id={pid} | url={flow.request.pretty_url}"
            if self.logger:
                self.logger.info(" 🧭 "+route_msg)
            else:
                print("🧭 "+route_msg)

            print(f"🎯 Session匹配成功！处理session-based attestor调用")
            self._process_session_based_attestor(flow, session_match)
            return

        # 原有逻辑：检查是否需要通过attestor处理
        if self._should_process_with_attestor(flow):
            self._process_with_attestor(flow)
        else:
            # 对于不需要attestor处理的请求，直接放行
            pass

        # 记录日志
        if self.logger:
            self.logger.info(f"处理请求: {flow.request.method} {flow.request.pretty_url}")

    def _maybe_handle_binding_request(self, flow: http.HTTPFlow) -> bool:
        """拦截并处理绑定请求: http://bind.reclaim.local/bind?session_id=xxx
        成功则返回204且记录连接-会话映射；返回True表示已处理该请求。
        """
        try:
            host = (flow.request.host or "").lower()
            path = urlparse(flow.request.pretty_url).path
            if host != self.binding_host or not path.startswith(self.binding_path):
                return False

            # 解析 session_id
            qs = parse_qs(urlparse(flow.request.pretty_url).query)
            session_id = (qs.get("session_id") or [""])[0]
            if not session_id:
                msg = {"error": "missing session_id"}
                flow.response = http.Response.make(400, json.dumps(msg).encode(), {"Content-Type": "application/json"})
                if self.logger:
                    self.logger.error(f"绑定失败: 缺少session_id, conn={flow.client_conn.id}")
                else:
                    print(f"❌ 绑定失败: 缺少session_id, conn={flow.client_conn.id}")
                return True

            conn_id = flow.client_conn.id
            peer = flow.client_conn.peername  # (ip, port)
            bind_info = {
                "session_id": session_id,
                "bound_at": time.time(),
                "ttl": self.binding_ttl_seconds,
                "peername": f"{peer[0]}:{peer[1]}" if isinstance(peer, tuple) and len(peer) >= 2 else str(peer),
            }
            self.connection_bindings[conn_id] = bind_info

            # 打印详细日志
            msg_lines = [
                "连接已绑定:",
                f"conn_id={conn_id}",
                f"peer={bind_info['peername']}",
                f"session_id={session_id}",
                f"ttl={self.binding_ttl_seconds}s"
            ]
            if self.logger:
                self.logger.info(" 🔗 "+" | ".join(msg_lines))
            else:
                print("🔗 "+" | ".join(msg_lines))

            flow.response = http.Response.make(204, b"", {})
            return True
        except Exception as e:
            msg = {"error": f"binding exception: {e}"}
            flow.response = http.Response.make(500, json.dumps(msg).encode(), {"Content-Type": "application/json"})
            if self.logger:
                self.logger.exception(f"绑定处理异常: {e}")
            else:
                print(f"❌ 绑定处理异常: {e}")
            return True

    def _maybe_log_binding_hit(self, flow: http.HTTPFlow) -> None:
        """如果该请求的连接已绑定，打印命中日志（仅日志，不拦截）。"""
        try:
            conn_id = flow.client_conn.id
            bind = self.connection_bindings.get(conn_id)
            if not bind:
                return
            # 简单打印一次命中日志（可考虑采样/频率限制）
            msg = f"命中绑定: conn_id={conn_id}, session_id={bind.get('session_id')}, host={flow.request.host}"
            if self.logger:
                self.logger.info(" 📎 "+msg)
            else:
                print("📎 "+msg)
        except Exception:
            pass

    def _attach_session_metadata(self, flow: http.HTTPFlow) -> None:
        """如该连接已绑定，将 session_id 等写入 flow.metadata，供后续匹配器优先直连使用。"""
        try:
            conn_id = flow.client_conn.id
            bind = self.connection_bindings.get(conn_id)
            if not bind:
                return
            flow.metadata["session_id"] = bind.get("session_id")
            flow.metadata["client_peer"] = bind.get("peername")
        except Exception:
            pass

    def _should_process_with_attestor(self, flow: http.HTTPFlow) -> bool:
        """判断是否需要通过attestor处理"""
        attestor_rules = self.config.get("attestor_rules", {})
        if not attestor_rules.get("enabled", False):
            return False

        host = flow.request.host
        path = urlparse(flow.request.pretty_url).path
        method = flow.request.method

        # 🚫 提前过滤开发环境静态资源，避免无意义的日志输出
        if self._is_dev_static_resource(host, path):
            return False

        # 调试输出
        print(f"🔍 检查请求: {method} {host}{path}")

        for rule in attestor_rules.get("rules", []):
            # 检查规则是否启用
            if not rule.get("enabled", True):
                continue

            # 检查域名匹配
            domains = rule.get("domains", [])
            if not self._match_domains(host, domains):
                continue

            # 检查路径匹配
            paths = rule.get("paths", [])
            if paths and not self._match_paths(path, paths):
                continue

            # 检查方法匹配
            methods = rule.get("methods", [])
            if methods and method not in methods:
                continue

            # 检查必需参数匹配
            required_params = rule.get("required_params", [])
            if required_params and not self._match_required_params(flow.request.pretty_url, required_params):
                print(f"⚪ 跳过请求（参数不匹配）: {method} {host}{path}")
                continue

            # 所有条件匹配
            print(f"✅ 匹配规则: {rule.get('name', 'Unknown')} - {method} {host}{path}")
            return True

        print(f"⚪ 跳过请求: {method} {host}{path}")
        return False

    def _is_dev_static_resource(self, host: str, path: str) -> bool:
        """判断是否为开发环境静态资源或非业务请求，避免无意义的处理和日志输出"""
        # 开发服务器特征（端口范围 3000-9999，localhost/127.0.0.1/10.x.x.x）
        is_dev_host = (
            'localhost' in host.lower() or
            host.startswith('127.0.0.1') or
            host.startswith('10.') or
            host.startswith('192.168.') or
            any(f':{port}' in host for port in range(3000, 10000))
        )

        # 静态资源文件扩展名
        static_extensions = {
            '.js', '.ts', '.jsx', '.tsx',           # JavaScript/TypeScript
            '.css', '.scss', '.sass', '.less',      # 样式文件
            '.html', '.htm',                        # HTML
            '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp',  # 图片
            '.woff', '.woff2', '.ttf', '.eot',      # 字体
            '.map',                                 # Source map
            '.json', '.xml',                        # 数据文件
            '.txt', '.md'                           # 文档
        }

        # 静态资源路径特征
        static_paths = {
            '/src/', '/assets/', '/static/', '/public/',
            '/js/', '/css/', '/img/', '/images/', '/fonts/',
            '/node_modules/', '/dist/', '/build/'
        }

        # 开发环境API路径特征（通常不是金融业务API）
        dev_api_paths = {
            '/home', '/api/task-sessions/', '/api/debug/', '/api/health/',
            '/api/status/', '/api/metrics/', '/api/logs/', '/health',
            '/status', '/ping', '/version', '/favicon.ico'
        }

        path_lower = path.lower()

        # 1. 开发环境：过滤静态资源和开发API
        if is_dev_host:
            # 检查文件扩展名
            if any(path_lower.endswith(ext) for ext in static_extensions):
                return True

            # 检查静态资源路径特征
            if any(segment in path_lower for segment in static_paths):
                return True

            # 检查开发环境API路径
            if any(path_lower.startswith(dev_path) or dev_path in path_lower for dev_path in dev_api_paths):
                return True

        # 2. 生产环境：只过滤明确的静态资源
        else:
            # 检查静态资源文件扩展名
            if any(path_lower.endswith(ext) for ext in static_extensions):
                return True

            # 检查静态资源路径特征
            if any(segment in path_lower for segment in static_paths):
                return True

        return False

    def _match_domains(self, host: str, domains: List[str]) -> bool:
        """匹配域名"""
        for domain in domains:
            if domain.startswith("*."):
                # 通配符匹配
                base_domain = domain[2:]
                if host.endswith(base_domain):
                    return True
            elif host == domain:
                return True
        return False

    def _match_paths(self, path: str, paths: List[str]) -> bool:
        """匹配路径"""
        import re
        for path_pattern in paths:
            try:
                if re.search(path_pattern, path):
                    return True
            except re.error:
                # 如果正则表达式无效，尝试前缀匹配
                if path.startswith(path_pattern):
                    return True
        return False

    def _match_required_params(self, url: str, required_params: List[str]) -> bool:
        """匹配必需参数"""
        for param in required_params:
            if param not in url:
                return False
        return True

    def _process_with_attestor(self, flow: http.HTTPFlow):
        """通过attestor处理请求"""
        try:
            # 统一路由日志（无 session 或未命中 session 的情况）
            sid = flow.metadata.get('session_id') if hasattr(flow, 'metadata') else None
            base_route_msg = f"路由选择: 规则匹配 | {'有session' if sid else '无session'}{(f'({sid})' if sid else '')} | url={flow.request.pretty_url}"
            if self.logger:
                self.logger.info(" 🧭 "+base_route_msg)
            else:
                print("🧭 "+base_route_msg)

            # 找到匹配的规则
            rule = self._find_matching_rule(flow)
            if not rule:
                # 如果没有匹配的规则，直接放行
                return

            # 只有明确匹配的请求才进行attestor处理
            print(f"🎯 Attestor处理请求: {flow.request.method} {flow.request.pretty_url}")
            print(f"   Headers: {dict(flow.request.headers)}")
            print(f"   Body: {flow.request.content.decode('utf-8', errors='ignore')[:200] if flow.request.content else 'Empty'}")

            # 转换为attestor参数
            attestor_params = self._convert_to_attestor_params(flow, rule)

            print(f"   转换后的参数:")
            print(f"   - URL: {attestor_params['params']['url']}")
            print(f"   - Method: {attestor_params['params']['method']}")
            print(f"   - Headers: {len(attestor_params['params']['headers'])} 个")
            print(f"   - SecretParams: 空对象")
            print(f"   - Response Patterns: {len(attestor_params['params'].get('responseMatches', []))} 个")

            # 创建响应回调
            def response_callback(result: Dict[str, Any]):
                self._handle_attestor_response(flow, result, rule)

            # 提交任务（直接传递attestor_params，不再生成命令行）
            task_id = self.executor.submit_task(attestor_params, response_callback)

            # 根据执行模式决定是否阻塞返回202或直通
            execution_mode = self.config.get("global_settings", {}).get("execution_mode", "blocking_ack")
            add_task_id_header = self.config.get("global_settings", {}).get("add_task_id_header", False)

            if add_task_id_header:
                try:
                    flow.request.headers["X-Attestor-Task-Id"] = task_id
                except Exception:
                    pass

            if execution_mode == "blocking_ack":
                # 暂时阻塞请求，返回处理中的响应
                flow.response = http.Response.make(
                    202,  # Accepted
                    json.dumps({
                        "status": "processing",
                        "message": "Request is being processed with attestor",
                        "task_id": task_id,
                        "url": flow.request.pretty_url,
                        "rule": rule.get("name", "Unknown")
                    }).encode(),
                    {"Content-Type": "application/json"}
                )

                # 记录待处理的响应，仅阻塞模式需要
                self.pending_responses[task_id] = flow
            else:
                # 非阻塞：不设置flow.response，允许请求继续上游
                pass

            self.metrics["attestor_requests"] += 1

            if self.logger:
                self.logger.info(f"Attestor处理请求: {task_id} - {flow.request.pretty_url}")

        except Exception as e:
            # 错误处理 - 但不阻止正常转发
            print(f"❌ Attestor处理异常: {e}")

            if self.logger:
                self.logger.error(f"Attestor处理失败: {e}")

            self.metrics["attestor_errors"] += 1

            # 不设置错误响应，让请求正常转发

    def _find_matching_rule(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
        """找到匹配的规则"""
        host = flow.request.host
        path = urlparse(flow.request.pretty_url).path
        method = flow.request.method

        for rule in self.config.get("attestor_rules", {}).get("rules", []):
            if (rule.get("enabled", True) and
                self._match_domains(host, rule.get("domains", [])) and
                self._match_paths(path, rule.get("paths", [])) and
                (not rule.get("methods") or method in rule.get("methods", [])) and
                (not rule.get("required_params") or self._match_required_params(flow.request.pretty_url, rule.get("required_params", [])))):
                return rule

        return None

    def _convert_to_attestor_params(self, flow: http.HTTPFlow, rule: Dict[str, Any]) -> Dict[str, Any]:
        """转换为attestor参数"""
        # 获取规则中的响应模式和地理位置
        response_patterns = rule.get("response_patterns", {})
        geo_location = rule.get("geo_location", "HK")

        # 使用转换器
        attestor_params = self.converter.convert_flow_to_attestor_params(
            flow,
            geo_location=geo_location,
            custom_patterns=response_patterns
        )

        return attestor_params

    def _handle_attestor_response(self, flow: http.HTTPFlow, result: Dict[str, Any], rule: Dict[str, Any]):
        """处理attestor响应"""
        task_id = result.get("task_id")

        execution_mode = self.config.get("global_settings", {}).get("execution_mode", "blocking_ack")

        # 非阻塞模式：不尝试写回客户端响应，只做落库/日志
        if execution_mode == "non_blocking":
            try:
                if result.get("success"):
                    self.metrics["attestor_success"] += 1
                else:
                    self.metrics["attestor_failures"] += 1
                if self.logger:
                    self.logger.info(f"Attestor任务完成(非阻塞): {task_id} success={result.get('success', False)}")
            except Exception:
                pass
            return

        # 阻塞模式下继续走原有回写流程
        # 检查连接状态
        if task_id not in self.pending_responses:
            print(f"⚠️  任务 {task_id} 未找到，跳过响应处理")
            return

        # 检查是否是断开的连接
        connection_closed = self.pending_responses[task_id] == "CONNECTION_CLOSED"

        try:
            if result.get("success"):
                # 成功情况 - 直接使用子进程返回的结构化数据
                receipt = result.get("receipt", {})
                extracted_params = result.get("extractedParameters", {})

                # 构建最终响应
                final_response = {
                    "status": "success",
                    "task_id": task_id,
                    "receipt": receipt,
                    "extractedParameters": extracted_params,
                    "processed_at": datetime.now().isoformat(),
                    "execution_time": result.get("execution_time", 0),
                    "timestamp": result.get("timestamp")
                }

                # 打印详细的成功日志
                print(f"🎉 Attestor任务 {task_id} 执行成功!")
                print(f"   执行时间: {result.get('execution_time', 0):.2f}秒")
                print(f"   规则: {rule.get('name', 'Unknown')}")

                if extracted_params:
                    print(f"   🎯 提取的参数: {extracted_params}")
                    # 如果是银行余额，特别显示
                    if any(key in str(extracted_params).lower() for key in ['hkd', 'usd', 'balance']):
                        print(f"   💰 银行余额信息已成功提取!")
                else:
                    print(f"   ⚠️  未提取到参数，检查响应匹配规则")

                if connection_closed:
                    print(f"   ⚠️  前端连接已断开，无法返回响应")
                else:
                    # 只有连接还在时才设置响应
                    flow.response = http.Response.make(
                        200,
                        json.dumps(final_response, ensure_ascii=False).encode(),
                        {"Content-Type": "application/json; charset=utf-8"}
                    )

                self.metrics["attestor_success"] += 1

            else:
                # 失败情况
                error_response = {
                    "status": "error",
                    "task_id": task_id,
                    "error": result.get("error", "Unknown error"),
                    "stderr": result.get("stderr", ""),
                    "processed_at": datetime.now().isoformat(),
                    "execution_time": result.get("execution_time", 0)
                }

                # 打印详细的失败日志
                print(f"❌ Attestor任务 {task_id} 执行失败!")
                print(f"   执行时间: {result.get('execution_time', 0):.2f}秒")
                print(f"   规则: {rule.get('name', 'Unknown')}")
                print(f"   错误: {result.get('error', 'Unknown error')}")
                print(f"   stderr: {result.get('stderr', '')}")

                if connection_closed:
                    print(f"   ⚠️  前端连接已断开，无法返回错误响应")
                else:
                    # 只有连接还在时才设置响应
                    flow.response = http.Response.make(
                        500,
                        json.dumps(error_response).encode(),
                        {"Content-Type": "application/json"}
                    )

                self.metrics["attestor_failures"] += 1

            if self.logger:
                self.logger.info(f"Attestor响应处理完成: {task_id}")

        except Exception as e:
            # 响应处理异常
            error_response = {
                "status": "error",
                "task_id": task_id,
                "error": f"Response processing failed: {str(e)}"
            }

            flow.response = http.Response.make(
                500,
                json.dumps(error_response).encode(),
                {"Content-Type": "application/json"}
            )

            if self.logger:
                self.logger.error(f"Attestor响应处理异常: {e}")

        finally:
            # 清理待处理响应（无论连接是否断开）
            if task_id in self.pending_responses:
                if connection_closed:
                    print(f"🧹 清理已断开连接的任务: {task_id}")
                del self.pending_responses[task_id]

    def _parse_attestor_output(self, stdout: str) -> Dict[str, Any]:
        """解析attestor输出"""
        try:
            # 查找 "🎯 完整的Claim对象JSON:" 标记后的JSON
            lines = stdout.strip().split('\n')
            json_start_index = -1

            for i, line in enumerate(lines):
                if "🎯 完整的Claim对象JSON:" in line:
                    json_start_index = i + 1
                    break

            if json_start_index >= 0:
                # 从标记后开始收集JSON行
                json_lines = []
                brace_count = 0
                started = False

                for i in range(json_start_index, len(lines)):
                    line = lines[i].strip()
                    if not line:
                        continue

                    if line.startswith('{'):
                        started = True

                    if started:
                        json_lines.append(line)
                        brace_count += line.count('{') - line.count('}')

                        if brace_count == 0:
                            # JSON对象结束
                            break

                if json_lines:
                    json_str = '\n'.join(json_lines)
                    receipt = json.loads(json_str)

                    # 提取关键信息
                    result = {
                        "parsed": True,
                        "receipt": receipt
                    }

                    # 提取 extractedParameters
                    if receipt.get("claim") and receipt["claim"].get("context"):
                        try:
                            context = json.loads(receipt["claim"]["context"])
                            if context.get("extractedParameters"):
                                result["extractedParameters"] = context["extractedParameters"]
                        except:
                            pass

                    return result

            # 如果没有找到标记，尝试直接解析JSON行
            for line in lines:
                line = line.strip()
                if line.startswith('{') and line.strip().endswith('}'):
                    try:
                        return {
                            "parsed": True,
                            "receipt": json.loads(line)
                        }
                    except:
                        continue

            # 如果没有找到JSON，返回原始输出
            return {
                "raw_output": stdout,
                "parsed": False
            }

        except Exception as e:
            return {
                "raw_output": stdout,
                "parse_error": str(e),
                "parsed": False
            }

    def error(self, flow: http.HTTPFlow) -> None:
        """处理连接错误"""
        self._cleanup_flow(flow)

    def _cleanup_flow(self, flow: http.HTTPFlow):
        """标记flow连接已断开，但不清理任务"""
        # 查找相关的pending response，标记为断开连接
        for task_id, pending_flow in self.pending_responses.items():
            if pending_flow == flow:
                print(f"🔌 前端连接断开，任务 {task_id} 将继续执行并打印结果")
                # 不删除pending_responses，而是标记为断开连接
                # 使用特殊标记来表示连接已断开
                self.pending_responses[task_id] = "CONNECTION_CLOSED"

    def done(self):
        """Addon结束时调用"""
        if self.logger:
            self.logger.info("AttestorForwardingAddon 结束运行")
            self.logger.info(f"处理统计: {dict(self.metrics)}")

        print(f"📊 Attestor转发统计: {dict(self.metrics)}")

        # 清理所有pending responses
        if self.pending_responses:
            print(f"🧹 清理 {len(self.pending_responses)} 个未完成的响应")
            self.pending_responses.clear()

    def _process_session_based_attestor(self, flow: http.HTTPFlow, session_match: Dict[str, Any]) -> None:
        """
        处理基于session匹配的attestor调用

        Args:
            flow: HTTP请求流
            session_match: session匹配结果
        """
        session = session_match['session']
        provider_id = session_match['provider_id']
        task_id = session_match['task_id']
        match_result = session_match['match_result']
        attestor_params = session_match.get('attestor_params', {})
        attestor_response = session_match['attestor_response']
        should_call_attestor = session_match['should_call_attestor']

        print(f"🎯 处理session-based attestor调用:")
        print(f"   Session ID: {session['id']}")
        print(f"   Provider ID: {provider_id}")
        print(f"   Task ID: {task_id}")
        print(f"   匹配URL: {match_result['matched_url']}")
        print(f"   需要调用attestor: {should_call_attestor}")

        # 读取执行模式
        execution_mode = self.config.get("global_settings", {}).get("execution_mode", "blocking_ack")
        add_task_id_header = self.config.get("global_settings", {}).get("add_task_id_header", False)

        if attestor_response:
            # 如果已有attestor响应
            print(f"✅ 使用已有的attestor响应")

            # 更新session状态为Finished
            from task_session_db import SessionStatus

            # 🎯 从已有的attestor响应中提取taskId
            attestor_task_id = None
            if isinstance(attestor_response, dict):
                attestor_task_id = attestor_response.get('task_id') or attestor_response.get('taskId')

            # 构建更新数据
            update_data = {
                'matched_url': match_result['matched_url'],
                'similarity_score': match_result['similarity_score'],
                'processed_by': 'session_based_matcher'
            }

            # 如果有attestor taskId，更新session的taskId
            if attestor_task_id:
                update_data['taskId'] = attestor_task_id
                print(f"🔄 更新session taskId (已有响应): {session.get('taskId')} -> {attestor_task_id}")

            self.session_matcher.task_session_db.update_session_status(
                session['id'],
                SessionStatus.FINISHED,
                update_data
            )

            # 根据执行模式决定是否拦截响应
            if add_task_id_header and isinstance(attestor_response, dict):
                try:
                    attach_id = attestor_response.get('task_id') or attestor_response.get('taskId') or task_id
                    if attach_id:
                        flow.request.headers["X-Attestor-Task-Id"] = str(attach_id)
                except Exception:
                    pass

            if execution_mode == "blocking_ack":
                # 直接将已有的attestor响应返回给客户端，避免上游调用
                try:
                    if attestor_response.get('success'):
                        final_response = {
                            "status": "success",
                            "task_id": attestor_response.get('task_id') or attestor_response.get('taskId') or task_id,
                            "receipt": attestor_response.get('receipt'),
                            "extractedParameters": attestor_response.get('extractedParameters', {}),
                            "processed_at": datetime.now().isoformat(),
                            "execution_time": attestor_response.get('execution_time', 0),
                            "timestamp": attestor_response.get('timestamp')
                        }
                        flow.response = http.Response.make(
                            200,
                            json.dumps(final_response, ensure_ascii=False).encode(),
                            {"Content-Type": "application/json; charset=utf-8"}
                        )
                    else:
                        error_response = {
                            "status": "error",
                            "task_id": attestor_response.get('task_id') or attestor_response.get('taskId') or task_id,
                            "error": attestor_response.get('error', 'Unknown error'),
                            "stderr": attestor_response.get('stderr', ''),
                            "processed_at": datetime.now().isoformat(),
                            "execution_time": attestor_response.get('execution_time', 0)
                        }
                        flow.response = http.Response.make(
                            500,
                            json.dumps(error_response, ensure_ascii=False).encode(),
                            {"Content-Type": "application/json; charset=utf-8"}
                        )
                except Exception as e:
                    print(f"❌ 写回已有attestor响应失败: {e}")
            else:
                # 非阻塞直通：不设置flow.response，允许继续转发
                pass

        elif should_call_attestor:
            # 需要调用attestor
            print(f"🚀 开始调用attestor...")

            # 获取provider配置
            provider = self.session_matcher.provider_query.get_provider_by_id(provider_id)
            if not provider:
                print(f"❌ 无法获取provider配置: {provider_id}（非阻塞直通，不拦截响应）")
                return

            # 在调用attestor之前，更新session状态为 Verifying
            try:
                from task_session_db import SessionStatus
                update_data = {
                    'matched_url': match_result['matched_url'],
                    'similarity_score': match_result['similarity_score'],
                    'processed_by': 'session_based_matcher',
                    'verifying_at': time.time()
                }
                self.session_matcher.task_session_db.update_session_status(
                    session['id'],
                    SessionStatus.VERIFYING,
                    update_data
                )
                print(f"🔄 Session状态已更新为: {SessionStatus.VERIFYING.value}")
            except Exception as e:
                print(f"⚠️ 调用前更新Session状态为Verifying失败: {e}")

            # 使用provider配置调用attestor
            self._call_attestor_with_provider_config(flow, provider, session, match_result, attestor_params)

        else:
            # 异常情况：不拦截响应
            print(f"⚠️  Session匹配成功但无法确定处理方式（非阻塞直通）")

    def _call_attestor_with_provider_config(self, flow: http.HTTPFlow, provider: Dict[str, Any],
                                          session: Dict[str, Any], match_result: Dict[str, Any],
                                          attestor_params: Dict[str, Any]) -> None:
        """
        使用provider配置调用attestor

        Args:
            flow: HTTP请求流
            provider: Provider配置
            session: Session记录
            match_result: URL匹配结果
            attestor_params: 已构建的attestor参数
        """
        try:
            # 使用已构建的attestor参数（包含provider的responseMatches和responseRedactions）
            if not attestor_params:
                print(f"❌ 没有提供attestor参数（非阻塞直通，不拦截响应）")
                return

            print(f"✅ 使用已构建的attestor参数")
            params = attestor_params.get('params', {})
            secret_params = attestor_params.get('secretParams', {})
            params_headers = params.get('headers', {})
            print(f"   URL: {params.get('url', '')[:100]}...")
            print(f"   方法: {params.get('method', '')}")
            print(f"   普通Headers数量: {len(params_headers)}")
            print(f"   SecretParams: {list(secret_params.keys())}")
            print(f"   ResponseMatches数量: {len(params.get('responseMatches', []))}")
            print(f"   ResponseRedactions数量: {len(params.get('responseRedactions', []))}")

            # 创建响应回调
            def response_callback(result: Dict[str, Any]):
                self._handle_session_based_attestor_response(flow, result, session, match_result)

            # 提交任务
            if not self.executor:
                print(f"❌ Attestor executor未初始化（非阻塞直通，不拦截响应）")
                return

            task_id = self.executor.submit_task(attestor_params, response_callback)

            execution_mode = self.config.get("global_settings", {}).get("execution_mode", "blocking_ack")
            add_task_id_header = self.config.get("global_settings", {}).get("add_task_id_header", False)

            if add_task_id_header:
                try:
                    flow.request.headers["X-Attestor-Task-Id"] = task_id
                except Exception:
                    pass

            if execution_mode == "blocking_ack":
                # 阻塞返回202，且不直通上游，避免重复调用
                try:
                    flow.response = http.Response.make(
                        202,
                        json.dumps({
                            "status": "processing",
                            "message": "Request is being processed with attestor (session)",
                            "task_id": task_id,
                            "url": flow.request.pretty_url,
                            "provider_id": (provider.get('id') if isinstance(provider, dict) else None)
                        }).encode(),
                        {"Content-Type": "application/json"}
                    )
                except Exception:
                    pass

                # 记录待处理的响应，供回调写回
                self.pending_responses[task_id] = flow
            else:
                # 非阻塞直通：不写flow.response
                pass

            print(f"🚀 Attestor任务已提交: {task_id}")

        except Exception as e:
            print(f"❌ 调用attestor失败（非阻塞直通，不拦截响应）: {e}")

    def _handle_session_based_attestor_response(self, flow: http.HTTPFlow, result: Dict[str, Any],
                                              session: Dict[str, Any], match_result: Dict[str, Any]) -> None:
        """
        处理session-based attestor响应

        Args:
            flow: HTTP请求流
            result: Attestor执行结果
            session: Session记录
            match_result: URL匹配结果
        """
        try:
            print(f"📨 收到session-based attestor响应: {session['id']}")

            # 更新session状态
            from task_session_db import SessionStatus
            status = SessionStatus.FINISHED if result.get('success') else SessionStatus.FAILED

            # 🎯 从attestor结果中提取taskId
            attestor_task_id = result.get('task_id') or result.get('taskId')

            # 执行模式
            execution_mode = self.config.get("global_settings", {}).get("execution_mode", "blocking_ack")

            # 🔍 详细分析attestor响应，特别是extractedParameters
            print(f"🔍 详细分析attestor响应:")
            print(f"   Success: {result.get('success', False)}")

            if 'claim' in result:
                claim = result['claim']
                print(f"   Claim存在: True")

                if 'context' in claim:
                    context_str = claim['context']
                    print(f"   Context: {context_str}")

                    try:
                        context_obj = json.loads(context_str)
                        print(f"   Context解析成功:")
                        print(f"     providerHash: {context_obj.get('providerHash', '缺失')}")

                        if 'extractedParameters' in context_obj:
                            extracted = context_obj['extractedParameters']
                            print(f"     ✅ extractedParameters: {extracted}")
                            print(f"     提取的字段数量: {len(extracted)}")
                        else:
                            print(f"     ❌ 缺少extractedParameters - 这是问题所在!")
                            print(f"     可能原因: responseRedactions的正则表达式没有匹配到响应内容")
                    except Exception as e:
                        print(f"   ❌ Context解析失败: {e}")
                else:
                    print(f"   ❌ 缺少context字段")

            # 构建更新数据
            update_data = {
                'matched_url': match_result['matched_url'],
                'similarity_score': match_result['similarity_score'],
                'processed_by': 'session_based_matcher',
                'completed_at': time.time()
            }

            # 🎯 只在attestor失败时写attestor_result字段（用于调试）
            if not result.get('success', False):
                update_data['attestor_result'] = result
                print(f"💾 Attestor失败，已保存结果到session用于调试")
            else:
                # 即使成功，如果没有extractedParameters也记录一下
                if 'claim' in result and 'context' in result['claim']:
                    try:
                        context_obj = json.loads(result['claim']['context'])
                        if 'extractedParameters' not in context_obj:
                            print(f"⚠️ Attestor成功但没有提取到参数，可能需要检查responseRedactions")
                    except:
                        pass

            # 如果有attestor taskId，更新session的taskId
            if attestor_task_id:
                update_data['taskId'] = attestor_task_id
                print(f"🔄 更新session taskId: {session.get('taskId')} -> {attestor_task_id}")

            self.session_matcher.task_session_db.update_session_status(
                session['id'],
                status,
                update_data
            )

            print(f"✅ Session状态已更新为: {status.value}")

            # 在阻塞模式下，尝试将最终响应写回原始请求（如果仍在pending）
            if execution_mode == "blocking_ack":
                task_id = attestor_task_id
                if not task_id:
                    # 如果缺少taskId，无法定位pending flow
                    return
                if task_id not in self.pending_responses:
                    print(f"⚠️  session-based 任务 {task_id} 未在pending中，跳过写回")
                    return
                connection_closed = self.pending_responses[task_id] == "CONNECTION_CLOSED"
                try:
                    if result.get('success'):
                        receipt = result.get('receipt', {})
                        extracted_params = result.get('extractedParameters', {})
                        final_response = {
                            "status": "success",
                            "task_id": task_id,
                            "receipt": receipt,
                            "extractedParameters": extracted_params,
                            "processed_at": datetime.now().isoformat(),
                            "execution_time": result.get("execution_time", 0),
                            "timestamp": result.get("timestamp")
                        }
                        if not connection_closed:
                            flow.response = http.Response.make(
                                200,
                                json.dumps(final_response, ensure_ascii=False).encode(),
                                {"Content-Type": "application/json; charset=utf-8"}
                            )
                    else:
                        error_response = {
                            "status": "error",
                            "task_id": task_id,
                            "error": result.get('error', 'Unknown error'),
                            "stderr": result.get('stderr', ''),
                            "processed_at": datetime.now().isoformat(),
                            "execution_time": result.get('execution_time', 0)
                        }
                        if not connection_closed:
                            flow.response = http.Response.make(
                                500,
                                json.dumps(error_response, ensure_ascii=False).encode(),
                                {"Content-Type": "application/json; charset=utf-8"}
                            )
                finally:
                    # 清理pending记录
                    try:
                        del self.pending_responses[task_id]
                    except Exception:
                        pass

        except Exception as e:
            print(f"❌ 处理session-based attestor响应失败: {e}")


# 全局addon实例
addons = [AttestorForwardingAddon()]
