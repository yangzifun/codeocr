# -*- coding: utf-8 -*-
# @Time    : 2025/7/11
# @Software: YZFN
import argparse
import ddddocr
from aiohttp import web
import base64
import aiohttp
import json
import os

print(
    "欢迎使用codeocr服务端脚本\n\n")
parser = argparse.ArgumentParser()

parser.add_argument("-p", help="http port", default="8888")
args = parser.parse_args()

# ==================== 关键修改点 ====================
# 在初始化时添加 show_ad=False 参数，以禁用ddddocr库的广告和欢迎信息输出
ocr = ddddocr.DdddOcr(show_ad=False)
# ===================================================

port = args.p

auth_base64 = "f0ngauth"  # 可自定义auth认证


def parse_raw_http_request(filepath="get.txt"):
    """
    解析一个包含原始HTTP请求的文件（如Burp Suite的原始请求）。
    :param filepath: 文件路径
    :return: a tuple containing (method, url, headers)
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"请求文件未找到: {filepath}")

    with open(filepath, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f if line.strip()]

    # 解析第一行: "GET /path/to/resource HTTP/1.1"
    first_line_parts = lines[0].split()
    method = first_line_parts[0]
    path = first_line_parts[1]

    # 解析请求头
    headers = {}
    for line in lines[1:]:
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()

    # 从 'Host' 头构建完整的URL
    host = headers.get('Host')
    if not host:
        raise ValueError("在请求文件中未找到 'Host' 头.")

    # 假设是 https 协议, 这在现代web应用中是标准的
    scheme = 'https'
    url = f"{scheme}://{host}{path}"

    # aiohttp 会自动处理 Host 和 Content-Length, 从headers中移除以避免冲突
    headers.pop('Host', None)

    return method, url, headers


# 识别纯整数0-9
async def handle_cb00(request):
    if request.headers.get('Authorization') != 'Basic ' + auth_base64:
        return web.Response(text='Forbidden', status='403')
    ocr.set_ranges(0)
    img_base64 = await request.text()
    img_bytes = base64.b64decode(img_base64)
    res = ocr.classification(img_bytes, probability=True)
    s = ""
    for i in res['probability']:
        s += res['charsets'][i.index(max(i))]
    print(s)
    return web.Response(text=s)


# 识别纯小写英文a-z
async def handle_cb01(request):
    if request.headers.get('Authorization') != 'Basic ' + auth_base64:
        return web.Response(text='Forbidden', status='403')
    ocr.set_ranges(1)
    img_base64 = await request.text()
    img_bytes = base64.b64decode(img_base64)
    res = ocr.classification(img_bytes, probability=True)
    s = ""
    for i in res['probability']:
        s += res['charsets'][i.index(max(i))]
    print(s)
    return web.Response(text=s)


# 识别纯大写英文A-Z
async def handle_cb02(request):
    if request.headers.get('Authorization') != 'Basic ' + auth_base64:
        return web.Response(text='Forbidden', status='403')
    ocr.set_ranges(2)
    img_base64 = await request.text()
    img_bytes = base64.b64decode(img_base64)
    res = ocr.classification(img_bytes, probability=True)
    s = ""
    for i in res['probability']:
        s += res['charsets'][i.index(max(i))]
    print(s)
    return web.Response(text=s)


# 识别小写英文a-z + 大写英文A-Z
async def handle_cb03(request):
    if request.headers.get('Authorization') != 'Basic ' + auth_base64:
        return web.Response(text='Forbidden', status='403')
    ocr.set_ranges(3)
    img_base64 = await request.text()
    img_bytes = base64.b64decode(img_base64)
    res = ocr.classification(img_bytes, probability=True)
    s = ""
    for i in res['probability']:
        s += res['charsets'][i.index(max(i))]
    print(s)
    return web.Response(text=s)


# 识别小写英文a-z + 整数0-9
async def handle_cb04(request):
    if request.headers.get('Authorization') != 'Basic ' + auth_base64:
        return web.Response(text='Forbidden', status='403')
    ocr.set_ranges(4)
    img_base64 = await request.text()
    img_bytes = base64.b64decode(img_base64)
    res = ocr.classification(img_bytes, probability=True)
    s = ""
    for i in res['probability']:
        s += res['charsets'][i.index(max(i))]
    print(s)
    return web.Response(text=s)


# 识别大写英文A-Z + 整数0-9
async def handle_cb05(request):
    if request.headers.get('Authorization') != 'Basic ' + auth_base64:
        return web.Response(text='Forbidden', status='403')
    ocr.set_ranges(5)
    img_base64 = await request.text()
    img_bytes = base64.b64decode(img_base64)
    res = ocr.classification(img_bytes, probability=True)
    s = ""
    for i in res['probability']:
        s += res['charsets'][i.index(max(i))]
    print(s)
    return web.Response(text=s)


# 识别小写英文a-z + 大写英文A-Z + 整数0-9
async def handle_cb06(request):
    if request.headers.get('Authorization') != 'Basic ' + auth_base64:
        return web.Response(text='Forbidden', status='403')
    ocr.set_ranges(6)
    img_base64 = await request.text()
    img_bytes = base64.b64decode(img_base64)
    res = ocr.classification(img_bytes, probability=True)
    s = ""
    for i in res['probability']:
        s += res['charsets'][i.index(max(i))]
    print(s)
    return web.Response(text=s)


# 识别自定义字符，默认为识别算术
async def handle_cb000(request):
    if request.headers.get('Authorization') != 'Basic ' + auth_base64:
        return web.Response(text='Forbidden', status='403')
    ocr.set_ranges(request.headers.get('ranges'))
    print(request.headers.get('ranges'))
    img_base64 = await request.text()
    img_bytes = base64.b64decode(img_base64)
    res = ocr.classification(img_bytes, probability=True)
    s = ""
    for i in res['probability']:
        s += res['charsets'][i.index(max(i))]
    print(s)
    if '+' in s:
        zhi = int(s.split('+')[0]) + int(s.split('+')[1][:-1])
        print(zhi)
        return web.Response(text=str(zhi))
    elif '-' in s:
        zhi = int(s.split('-')[0]) - int(s.split('-')[1][:-1])
        print(zhi)
        return web.Response(text=str(zhi))
    elif '*' in s:
        zhi = int(s.split('*')[0]) * int(s.split('*')[1][:-1])
        print(zhi)
        return web.Response(text=str(zhi))
    elif 'x' in s:
        zhi = int(s.split('x')[0]) * int(s.split('x')[1][:-1])
        print(zhi)
        return web.Response(text=str(zhi))
    elif '/' in s:
        zhi = int(s.split('/')[0]) / int(s.split('/')[1][:-1])
        return web.Response(text=str(zhi))
    else:
        return web.Response(text=s)


# 识别常规验证码
async def handle_cb2(request):
    if request.headers.get('Authorization') != 'Basic ' + auth_base64:
        return web.Response(text='Forbidden', status='403')
    img_base64 = await request.text()
    img_bytes = base64.b64decode(img_base64)
    res = ocr.classification(img_bytes)
    print(res)
    return web.Response(text=ocr.classification(img_bytes)[0:10])


# 识别算术验证码
async def handle_cb(request):
    zhi = ""
    if request.headers.get('Authorization') != 'Basic ' + auth_base64:
        return web.Response(text='Forbidden', status='403')
    img_base64 = await request.text()
    img_bytes = base64.b64decode(img_base64)
    res = ocr.classification(img_bytes).replace("=", "").replace("?", "")
    print(res)
    if '+' in res:
        zhi = int(res.split('+')[0]) + int(res.split('+')[1][:-1])
        print(zhi)
        return web.Response(text=str(zhi))
    elif '-' in res:
        zhi = int(res.split('-')[0]) - int(res.split('-')[1][:-1])
        print(zhi)
        return web.Response(text=str(zhi))
    elif '*' in res:
        zhi = int(res.split('*')[0]) * int(res.split('*')[1][:-1])
        print(zhi)
        return web.Response(text=str(zhi))
    elif 'x' in res:
        zhi = int(res.split('x')[0]) * int(res.split('x')[1][:-1])
        print(zhi)
        return web.Response(text=str(zhi))
    elif '/' in res:
        zhi = int(res.split('/')[0]) / int(res.split('/')[1][:-1])
        return web.Response(text=str(zhi))
    else:
        return web.Response(text=res)


# ==================== 新增功能：从get.txt文件读取请求并发起识别 ====================
async def handle_get_and_solve(request):
    """
    该函数处理一个GET请求。它会读取 get.txt 文件，
    解析出请求详情（URL, Headers），然后发起这个请求以获取验证码，
    最后进行识别并返回结果。
    """
    try:
        # 1. 从 get.txt 动态解析请求参数
        method, target_url, headers = parse_raw_http_request('get.txt')

        # 确保方法是GET
        if method.upper() != 'GET':
            return web.json_response({'error': f"不支持的方法: {method}. 'get.txt' 必须是一个GET请求."}, status=400)

        print(f"从 'get.txt' 解析到请求: {method.upper()} {target_url}")

        # 2. 使用解析出的参数发起异步GET请求
        async with aiohttp.ClientSession() as session:
            # UAT环境可能使用自签名证书，添加 ssl=False 以避免校验错误
            async with session.get(target_url, headers=headers, ssl=False) as response:

                # 3. 检查响应状态并解析
                if response.status == 200:
                    # 尝试解析JSON响应
                    try:
                        data = await response.json()
                    except:
                        # 如果JSON解析失败，尝试作为文本处理
                        text = await response.text()
                        return web.json_response({
                            'error': '目标服务器返回了非JSON响应',
                            'content': text
                        }, status=500)

                    image_data_uri = data.get('image')
                    captcha_key = data.get('key')

                    if not image_data_uri:
                        return web.json_response({'error': "从目标服务器响应中未找到 'image' 字段"}, status=500)

                    # 4. 提取并解码Base64图片数据
                    try:
                        # 分割 "data:image/png;base64," 和实际的base64字符串
                        _, base64_str = image_data_uri.split(',', 1)
                        img_bytes = base64.b64decode(base64_str)
                    except Exception as e:
                        return web.json_response({'error': f'Base64 解码失败: {e}'}, status=500)

                    # 5. 使用 ddddocr 进行识别
                    result = ocr.classification(img_bytes)

                    print(f"远程获取验证码成功. Key: {captcha_key}, 识别结果: {result}")

                    # 6. 将结果以JSON格式返回
                    return web.json_response({
                        "success": True,
                        "key": captcha_key,
                        "result": result
                    }, status=200)
                else:
                    error_text = await response.text()
                    print(f"请求目标失败: {response.status}, 详情: {error_text}")
                    return web.json_response({
                        'error': '请求目标服务器验证码失败',
                        'status_code': response.status,
                        'details': error_text
                    }, status=502)

    except (FileNotFoundError, ValueError) as e:
        # 捕获文件未找到或解析错误
        print(f"错误: {e}")
        return web.json_response({'error': str(e)}, status=500)
    except Exception as e:
        # 捕获其他所有异常
        import traceback
        traceback.print_exc()
        return web.json_response({'error': f'发生未知错误: {str(e)}'}, status=500)


# ==============================================================================


app = web.Application()
app.add_routes([
    web.post('/reg2', handle_cb),
    web.post('/reg', handle_cb2),
    web.post('/reg00', handle_cb00),
    web.post('/reg01', handle_cb01),
    web.post('/reg02', handle_cb02),
    web.post('/reg03', handle_cb03),
    web.post('/reg04', handle_cb04),
    web.post('/reg05', handle_cb05),
    web.post('/reg06', handle_cb06),
    web.post('/reg000', handle_cb000),

    # ======= 注册新的路由 =======
    web.get('/get_and_solve', handle_get_and_solve),
])

if __name__ == '__main__':
    # 确保 get.txt 文件存在于脚本同一目录下
    if not os.path.exists('get.txt'):
        print("\n[错误] 'get.txt' 文件未找到! 请确保该文件与Python脚本在同一目录下。\n")
    else:
        web.run_app(app, port=int(port))
