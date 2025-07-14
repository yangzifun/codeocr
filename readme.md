## **准备模板**

- 在与 `ocr_server.py` 相同的目录下，创建一个名为 `requests_templates` 的文件夹。
- 在 `requests_templates` 文件夹中，放入多个 `.txt` 文件，例如，`login_captcha.txt`, `register_captcha.txt`, `uat_env_captcha.txt` 等。每个文件包含一个完整的原始GET请求。

将你从Yakit捕获的**原始GET请求**内容粘贴到 `.txt` 文件中。例如：

```
GET /api/captcha/get?t=1678888888888 HTTP/1.1
Host: your-target-website.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
Referer: https://your-target-website.com/login
Cookie: session=xyzabc123
```

## ** 测试模板**

1、运行ocr.py `python 版本 3.12`

```
pip install -r requirements.txt

python ocr.py
```

2、使用浏览器或`curl`访问 `http://127.0.0.1:8888/templates` 查看模板

```
{
    "status": "success",
    "available_templates": [
        "login_captcha.txt",
        "register_captcha.txt",
        "uat_env_captcha.txt"
    ]
}
```

## **执行特定模板的识别任务**

> 根据上一步返回的列表，选择一个模板进行调用；例如，要使用`get.txt`
>
>  `http://127.0.0.1:8888/get_and_solve?template=get.txt`

```
{"status": "success", "key": "133443c1ff3cf1f3146caffe9d031a04", "result": "wct2d"}
```

### ![A2687A4A-57C0-44E2-BE6D-07946B99B402.png](https://s3.yangzihome.space/BBS/A2687A4A-57C0-44E2-BE6D-07946B99B402.png)