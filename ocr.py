# -*- coding: utf-8 -*-
# @Time    : 2025/7/11 (Refactored for Multi-Template support)
# @Software: YZFN (Refactored by Senior Software Engineer)

import argparse
import base64
import json
import logging
import os
from pathlib import Path
from typing import List

import aiohttp
import ddddocr
from aiohttp import web

# --- 1. 初始化配置 (Initialization & Configuration) ---

# 使用 logging 模块记录信息，是生产环境的最佳实践
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 定义存放请求模板的安全目录
TEMPLATES_DIR = Path("requests_templates")

# 初始化 OCR 引擎
try:
    ocr = ddddocr.DdddOcr(show_ad=False)
    logging.info("ddddocr引擎初始化成功。")
except Exception as e:
    logging.error(f"ddddocr引擎初始化失败: {e}")
    exit(1)  # 如果核心组件失败，则退出程序


# --- 2. 核心辅助函数 (Core Helper Functions) ---

def parse_raw_http_request(filepath: Path):
    """
    从一个安全路径下的文件解析原始HTTP GET请求。
    (此函数保持不变)
    """
    if not filepath.is_file():
        raise FileNotFoundError(f"请求模板文件未找到: {filepath}")

    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read().strip()
        if not content:
            raise ValueError(f"请求模板文件为空: {filepath}")
        lines = content.splitlines()

    first_line_parts = lines[0].split()
    if len(first_line_parts) < 2:
        raise ValueError("请求行格式无效。")
    method = first_line_parts[0].upper()
    path = first_line_parts[1]

    if method != 'GET':
        raise ValueError(f"仅支持GET方法, 但在文件中找到 '{method}'。")

    headers = {}
    for line in lines[1:]:
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()

    host = headers.get('Host')
    if not host:
        raise ValueError("在请求文件中未找到 'Host' 头。")

    headers.pop('Host', None)
    headers.pop('Content-Length', None)

    scheme = headers.get('X-Forwarded-Proto', 'https')
    url = f"{scheme}://{host}{path}"

    return method, url, headers


# --- 3. aiohttp 请求处理器 (Request Handlers) ---

# 新增：列出所有可用的请求模板
async def list_available_templates(request: web.Request) -> web.Response:
    """
    扫描并返回 requests_templates 目录中所有可用的 .txt 模板文件。
    """
    logging.info("收到模板列表请求 /templates")
    if not TEMPLATES_DIR.is_dir():
        return web.json_response(
            {'status': 'error', 'message': f"模板目录 '{TEMPLATES_DIR}' 不存在。"},
            status=500
        )

    try:
        # 仅查找以 .txt 结尾的文件，更安全、更精确
        templates: List[str] = [f.name for f in TEMPLATES_DIR.glob('*.txt') if f.is_file()]
        logging.info(f"发现 {len(templates)} 个可用模板。")
        return web.json_response({
            'status': 'success',
            'available_templates': templates
        })
    except Exception as e:
        logging.error(f"扫描模板目录时发生错误: {e}", exc_info=True)
        return web.json_response({'status': 'error', 'message': '扫描模板目录时发生未知错误。'}, status=500)


async def handle_get_and_solve(request: web.Request) -> web.Response:
    """
    根据指定的模板文件，获取并识别验证码。
    """
    try:
        # 从查询参数获取模板文件名，如果没有提供则报错
        template_name = request.query.get('template')
        if not template_name:
            return web.json_response(
                {'status': 'error',
                 'message': "缺少 'template' 查询参数。请使用 ?template=<your_template_file.txt> 指定模板。"},
                status=400
            )

        # 安全性检查：防止路径遍历攻击
        if '..' in template_name or os.path.isabs(template_name) or '/' in template_name or '\\' in template_name:
            logging.warning(f"检测到潜在的路径遍历攻击: {template_name}")
            return web.json_response(
                {'status': 'error', 'message': '无效的模板文件名。'},
                status=400
            )

        template_path = TEMPLATES_DIR / template_name

        # 解析HTTP请求模板
        method, target_url, headers = parse_raw_http_request(template_path)
        logging.info(f"使用模板 '{template_name}' -> {method} {target_url}")

        # 使用aiohttp发起异步请求获取验证码
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get(target_url, ssl=False) as response:

                # 处理目标服务器的响应
                if response.status != 200:
                    error_text = await response.text()
                    logging.error(f"请求目标服务器失败: {response.status}, 详情: {error_text[:200]}")
                    return web.json_response({
                        'status': 'error',
                        'message': '请求目标验证码服务器失败。',
                        'target_status_code': response.status,
                        'target_response': error_text[:200]
                    }, status=502)

                # 解析JSON响应并提取图片数据
                try:
                    data = await response.json()
                except aiohttp.ContentTypeError:
                    return web.json_response({'status': 'error', 'message': '目标服务器返回了非JSON格式的响应。'},
                                             status=500)

                image_data_uri = data.get('image')
                captcha_key = data.get('key')
                if not image_data_uri:
                    return web.json_response({'status': 'error', 'message': "从目标服务器响应中未找到 'image' 字段。"},
                                             status=500)

                # 解码Base64图片并进行OCR识别
                _, base64_str = image_data_uri.split(',', 1)
                img_bytes = base64.b64decode(base64_str)
                result = ocr.classification(img_bytes)
                logging.info(f"验证码识别成功. Key: {captcha_key}, 识别结果: {result}")

                # 返回成功结果
                return web.json_response({
                    "status": "success",
                    "key": captcha_key,
                    "result": result
                }, status=200)

    except FileNotFoundError as e:
        logging.warning(f"请求的模板文件不存在: {e}")
        return web.json_response({'status': 'error', 'message': str(e)}, status=404)
    except ValueError as e:
        logging.error(f"模板文件格式错误: {e}")
        return web.json_response({'status': 'error', 'message': f'模板文件内容格式错误: {e}'}, status=400)
    except Exception as e:
        logging.error(f"发生未知服务器错误: {e}", exc_info=True)
        return web.json_response({'status': 'error', 'message': '发生未知服务器内部错误。'}, status=500)


# --- 4. 应用启动入口 (Application Entrypoint) ---

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="一个通过原始HTTP请求模板获取并识别验证码的API服务。")
    parser.add_argument("-p", "--port", help="服务监听的HTTP端口", default="8888")
    args = parser.parse_args()

    # 检查并创建模板目录
    if not TEMPLATES_DIR.exists():
        logging.info(f"模板目录 '{TEMPLATES_DIR}' 不存在，正在创建...")
        TEMPLATES_DIR.mkdir()
        logging.info(f"请将你的原始HTTP请求文件（以.txt结尾）放入 '{TEMPLATES_DIR}' 目录中。")
    else:
        logging.info(f"将从 '{TEMPLATES_DIR}' 目录加载请求模板。")

    app = web.Application()
    app.add_routes([
        web.get('/get_and_solve', handle_get_and_solve),
        # 注册新的API端点
        web.get('/templates', list_available_templates),
    ])

    logging.info(f"服务启动，监听端口 {args.port}...")
    logging.info(f"使用 'GET /templates' 查看所有可用的请求模板。")
    logging.info(f"使用 'GET /get_and_solve?template=<filename>' 执行识别任务。")

    web.run_app(app, port=int(args.port))
