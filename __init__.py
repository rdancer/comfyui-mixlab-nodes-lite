#
import os
import subprocess
import importlib.util
import sys,json
import execution
import uuid
import hashlib
import datetime
import folder_paths
import logging
import base64,io,re
import random
from PIL import Image
from comfy.cli_args import args
python = sys.executable

#修复 sys.stdout.isatty()  object has no attribute 'isatty'
try:
    sys.stdout.isatty()
except:
    print('#fix sys.stdout.isatty')
    sys.stdout.isatty = lambda: False

_URL_=None


from server import PromptServer

try:
    import aiohttp
    from aiohttp import web
except ImportError:
    print("Module 'aiohttp' not installed. Please install it via:")
    print("pip install aiohttp")
    print("or")
    print("pip install -r requirements.txt")
    sys.exit()


def is_installed(package, package_overwrite=None,auto_install=True):
    is_has=False
    try:
        spec = importlib.util.find_spec(package)
        is_has=spec is not None
    except ModuleNotFoundError:
        pass

    package = package_overwrite or package

    if spec is None:
        if auto_install==True:
            print(f"Installing {package}...")
            # 清华源 -i https://pypi.tuna.tsinghua.edu.cn/simple
            command = f'"{python}" -m pip install {package}'

            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, env=os.environ)

            is_has=True

            if result.returncode != 0:
                print(f"Couldn't install\nCommand: {command}\nError code: {result.returncode}")
                is_has=False
    else:
        print(package+'## OK')

    return is_has

try:
    import OpenSSL
except ImportError:
    print("Module 'pyOpenSSL' not installed. Please install it via:")
    print("pip install pyOpenSSL")
    print("or")
    print("pip install -r requirements.txt")
    is_installed('pyOpenSSL')
    sys.exit()

try:
    import watchdog
except ImportError:
    print("Module 'watchdog' not installed. Please install it via:")
    print("pip install watchdog")
    print("or")
    print("pip install -r requirements.txt")
    is_installed('watchdog')
    sys.exit()




current_path = os.path.abspath(os.path.dirname(__file__))


def remove_base64_prefix(base64_str):
  """
  去除 base64 字符串中的 data:image/*;base64, 前缀

  Args:
    base64_str: base64 编码的字符串

  Returns:
    去除前缀后的 base64 字符串
  """

  # 使用正则表达式匹配常见的前缀
  pattern = r'^data:image\/(.*);base64,(.+)$'
  match = re.match(pattern, base64_str)
  if match:
    # 如果匹配到常见的前缀，则去除前缀并返回
    return match.group(2)
  else:
    # 如果不匹配到常见的前缀，则直接返回
    return base64_str

def calculate_md5(string):
    encoded_string = string.encode()
    md5_hash = hashlib.md5(encoded_string).hexdigest()
    return md5_hash


def create_key(key_p,crt_p):
    import OpenSSL
    # 生成自签名证书
    # 生成私钥
    private_key = OpenSSL.crypto.PKey()
    private_key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

    # 生成CSR
    csr = OpenSSL.crypto.X509Req()
    csr.get_subject().CN = "mixlab.com"  # 设置证书的通用名称
    csr.set_pubkey(private_key)
    csr.sign(private_key, "sha256")
    # 生成证书
    certificate = OpenSSL.crypto.X509()
    certificate.set_serial_number(1)
    certificate.gmtime_adj_notBefore(0)
    certificate.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # 设置证书的有效期
    certificate.set_issuer(csr.get_subject())
    certificate.set_subject(csr.get_subject())
    certificate.set_pubkey(csr.get_pubkey())
    certificate.sign(private_key, "sha256")
    # 保存私钥到文件
    with open(key_p, "wb") as f:
        f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, private_key))

    # 保存证书到文件
    with open(crt_p, "wb") as f:
        f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate))
    return


def create_for_https():
    # print("#####path::", current_path)
    https_key_path=os.path.join(current_path, "https")
    crt=os.path.join(https_key_path, "certificate.crt")
    key=os.path.join(https_key_path, "private.key")
    # print("##https_key_path", crt,key)
    if not os.path.exists(https_key_path):
        # 使用mkdir()方法创建新目录
        os.mkdir(https_key_path)
    if not os.path.exists(crt):
        create_key(key,crt)
    # print('https_key OK: ', crt,key)
    return (crt,key)



# workflow  目录下的所有json
def read_workflow_json_files_all(folder_path):
    # print('#read_workflow_json_files_all',folder_path)
    json_files = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith('.json'):
                json_files.append(os.path.join(root, file))

    data = []
    for file_path in json_files:
        try:
            with open(file_path) as json_file:
                json_data = json.load(json_file)
                creation_time = datetime.datetime.fromtimestamp(os.path.getctime(file_path))
                numeric_timestamp = creation_time.timestamp()
                file_info = {
                    'filename': os.path.basename(file_path),
                    'category': os.path.dirname(file_path),
                    'data': json_data,
                    'date': numeric_timestamp
                }
                data.append(file_info)
        except Exception as e:
            print(e)

    sorted_data = sorted(data, key=lambda x: x['date'], reverse=True)
    return sorted_data

# workflow
def read_workflow_json_files(folder_path ):
    json_files = []
    for filename in os.listdir(folder_path):
        if filename.endswith('.json'):
            json_files.append(filename)

    data = []
    for file in json_files:
        file_path = os.path.join(folder_path, file)
        try:
            with open(file_path) as json_file:
                json_data = json.load(json_file)
                creation_time=datetime.datetime.fromtimestamp(os.path.getctime(file_path))
                numeric_timestamp = creation_time.timestamp()
                file_info = {
                    'filename': file,
                    'data': json_data,
                    'date': numeric_timestamp
                }
                data.append(file_info)
        except Exception as e:
            print(e)
    sorted_data = sorted(data, key=lambda x: x['date'], reverse=True)
    return sorted_data

def get_workflows():
    # print("#####path::", current_path)
    workflow_path=os.path.join(current_path, "workflow")
    # print('workflow_path: ',workflow_path)
    if not os.path.exists(workflow_path):
        # 使用mkdir()方法创建新目录
        os.mkdir(workflow_path)
    workflows=read_workflow_json_files(workflow_path)
    return workflows

def get_my_workflow_for_app(filename="my_workflow_app.json",category="",is_all=False):
    app_path=os.path.join(current_path, "app")
    if not os.path.exists(app_path):
        os.mkdir(app_path)

    category_path=os.path.join(app_path,category)
    if not os.path.exists(category_path):
        os.mkdir(category_path)

    apps=[]
    if filename==None:

        #TODO 支持目录内遍历
        if is_all:
            data=read_workflow_json_files_all(category_path)
        else:
            data=read_workflow_json_files(category_path)

        i=0
        for item in data:
            # print(item)
            try:
                x=item["data"]
                # 管理员模式，读取全部数据
                if i==0 or is_all:
                    apps.append({
                        "filename":item["filename"],
                        # "category":item['category'],
                        "data":x,
                        "date":item["date"],
                    })
                else:
                    category=''
                    input=None
                    output=None
                    if 'category' in x['app']:
                        category=x['app']['category']
                    if 'input' in x['app']:
                        input=x['app']['input']
                    if 'output' in x['app']:
                        output=x['app']['output']
                    apps.append({
                        "filename":item["filename"],
                        "category":category,
                        "data":{
                            "app":{
                                "category":category,
                                "description":x['app']['description'],
                                "filename":(x['app']['filename'] if 'filename' in x['app'] else "") ,
                                "icon":(x['app']['icon'] if 'icon' in x['app'] else None),
                                "name":x['app']['name'],
                                "version":x['app']['version'],
                                "input":input,
                                "output":output,
                                "id":x['app']['id']
                            }
                        },
                        "date":item["date"]
                    })
                i+=1
            except Exception as e:
                print("发生异常：", str(e))
    else:
        app_workflow_path=os.path.join(category_path, filename)
        print('app_workflow_path: ',app_workflow_path)
        try:
            with open(app_workflow_path) as json_file:
                json_data=json.load(json_file)
                apps = [{
                    'filename':filename,
                    'data':json_data
                }]
        except Exception as e:
            print("发生异常：", str(e))

        # 这个代码不需要
        # if len(apps)==1 and category!='' and category!=None:
        data=read_workflow_json_files(category_path)

        for item in data:
            x=item["data"]
            # print(apps[0]['filename'] ,item["filename"])
            if apps[0]['filename']!=item["filename"]:
                category=''
                input=None
                output=None
                if 'category' in x['app']:
                    category=x['app']['category']
                if 'input' in x['app']:
                    input=x['app']['input']
                if 'output' in x['app']:
                    output=x['app']['output']
                apps.append({
                        "filename":item["filename"],
                        # "category":category,
                        "data":{
                            "app":{
                                "category":category,
                                "description":x['app']['description'],
                                "filename":(x['app']['filename'] if 'filename' in x['app'] else "") ,
                                "icon":(x['app']['icon'] if 'icon' in x['app'] else None),
                                "name":x['app']['name'],
                                "version":x['app']['version'],
                                "input":input,
                                "output":output,
                                "id":x['app']['id']
                            }
                        },
                        "date":item["date"]
                    })

    return apps

# 历史记录
def save_prompt_result(id,data):
    prompt_result_path=os.path.join(current_path, "workflow/prompt_result.json")
    prompt_result={}
    if os.path.exists(prompt_result_path):
        with open(prompt_result_path) as json_file:
            prompt_result = json.load(json_file)

    prompt_result[id]=data

    with open(prompt_result_path, 'w') as file:
        json.dump(prompt_result, file)
    return prompt_result_path

def get_prompt_result():
    prompt_result_path=os.path.join(current_path, "workflow/prompt_result.json")
    prompt_result={}
    if os.path.exists(prompt_result_path):
        with open(prompt_result_path) as json_file:
            prompt_result = json.load(json_file)
    res=list(prompt_result.values())
    # print(res)
    return res


def save_workflow_json(data):
    workflow_path=os.path.join(current_path, "workflow/my_workflow.json")
    with open(workflow_path, 'w') as file:
        json.dump(data, file)
    return workflow_path

def save_workflow_for_app(data,filename="my_workflow_app.json",category=""):
    app_path=os.path.join(current_path, "app")
    if not os.path.exists(app_path):
        os.mkdir(app_path)

    category_path=os.path.join(app_path,category)
    if not os.path.exists(category_path):
        os.mkdir(category_path)

    app_workflow_path=os.path.join(category_path, filename)

    try:
        output_str = json.dumps(data['output'])
        data['app']['id']=calculate_md5(output_str)
        # id=data['app']['id']
    except Exception as e:
        print("发生异常：", str(e))

    with open(app_workflow_path, 'w') as file:
        json.dump(data, file)
    return filename

def get_nodes_map():
    # print("#####path::", current_path)
    data_path=os.path.join(current_path, "data")
    print('data_path: ',data_path)
    # if not os.path.exists(data_path):
    #     # 使用mkdir()方法创建新目录
    #     os.mkdir(data_path)
    json_data={}
    nodes_map=os.path.join(current_path, "data/extension-node-map.json")
    if os.path.exists(nodes_map):
        with open(nodes_map) as json_file:
            json_data = json.load(json_file)

    return json_data


# 保存原始的 get 方法
_original_request = aiohttp.ClientSession._request

# 定义新的 get 方法
async def new_request(self, method, url, *args, **kwargs):
   # 检查环境变量以确定是否使用代理
    proxy = os.environ.get('HTTP_PROXY') or os.environ.get('HTTPS_PROXY') or os.environ.get('http_proxy') or os.environ.get('https_proxy')
    # print('Proxy Config:',proxy)
    if proxy and 'proxy' not in kwargs:
        kwargs['proxy'] = proxy
        print('Use Proxy:',proxy)
    # 调用原始的 _request 方法
    return await _original_request(self, method, url, *args, **kwargs)

# 应用 Monkey Patch
aiohttp.ClientSession._request = new_request
import socket

async def check_port_available(address, port):
    #检查端口是否可用
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((address, port))
            return True
        except socket.error:
            return False

# https
async def new_start(self, address, port, verbose=True, call_on_start=None):
    global _URL_
    try:
        runner = web.AppRunner(self.app, access_log=None)
        await runner.setup()

        # if not await check_port_available(address, port):
        #     raise RuntimeError(f"Port {port} is already in use.")

        http_success = False
        http_port=port
        for i in range(11):  # 尝试最多11次
            if await check_port_available(address, port + i):
                http_port = port + i
                site = web.TCPSite(runner, address, http_port)
                await site.start()
                http_success = True
                break

        if not http_success:
            raise RuntimeError(f"Ports {port} to {port + 10} are all in use.")


        # site = web.TCPSite(runner, address, port)
        # await site.start()

        ssl_context = None
        scheme = "http"
        try:
            # 跟着本体修改
            if args.tls_keyfile and args.tls_certfile:
                scheme = "https"
                ssl_context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_SERVER, verify_mode=ssl.CERT_NONE)
                ssl_context.load_cert_chain(certfile=args.tls_certfile,
                                    keyfile=args.tls_keyfile)
            else:
                # 如果没传，则自动创建
                import ssl
                crt, key = create_for_https()
                ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                ssl_context.load_cert_chain(crt, key)
        except:
            import ssl
            crt, key = create_for_https()
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(crt, key)


        success = False
        for i in range(11):  # 尝试最多11次
            if await check_port_available(address, http_port + 1 + i):
                https_port = http_port + 1 + i
                site2 = web.TCPSite(runner, address, https_port, ssl_context=ssl_context)
                await site2.start()
                success = True
                break

        if not success:
            raise RuntimeError(f"Ports {http_port + 1} to {http_port + 10} are all in use.")

        if address == '':
            address = '127.0.0.1'
        if address=='0.0.0.0':
            address = '127.0.0.1'

        if verbose:

            logging.info("\n")
            logging.info("\n\nStarting server")

            import socket

            hostname = socket.gethostname()
            # logging.debug("hostname:", hostname)
            try:
                ip_address = socket.gethostbyname(hostname)
            except Exception as e:
                logging.debug("[mixlab]gethostbyname() downgraded due to exception:", e)
                ip_address = socket.gethostbyname("")

            # print(f"本机的 IP 地址是：{ip_address}")

            # print("\033[93mStarting server\n")
            logging.info("\033[93mTo see the GUI go to: http://{}:{} or http://{}:{}".format(ip_address, http_port,address,http_port))
            logging.info("\033[93mTo see the GUI go to: https://{}:{} or https://{}:{}\033[0m".format(ip_address, https_port,address,https_port))

            _URL_="http://{}:{}".format(address,http_port)
            # print("\033[93mTo see the GUI go to: http://{}:{}".format(address, http_port))
            # print("\033[93mTo see the GUI go to: https://{}:{}\033[0m".format(address, https_port))

        if call_on_start is not None:
            try:
                if scheme=='https':
                    call_on_start(scheme,address, https_port)
                else:
                    call_on_start(scheme,address, http_port)
            except:
                call_on_start(address,http_port)


    except Exception as e:
        print(f"Error starting the server: {e}")

        # import webbrowser
        # if os.name == 'nt' and address == '0.0.0.0':
        #     address = '127.0.0.1'
        # webbrowser.open(f"https://{address}")
        # webbrowser.open(f"http://{address}:{port}")

PromptServer.start=new_start

# 创建路由表
routes = PromptServer.instance.routes

@routes.post('/mixlab')
async def mixlab_hander(request):
    config=os.path.join(current_path, "nodes/config.json")
    data={}
    try:
        if os.path.exists(config):
            with open(config, 'r') as f:
                data = json.load(f)
                # print(data)
    except Exception as e:
            print(e)
    return web.json_response(data)

# llm的api key，使用硅基流动
@routes.post('/mixlab/llm_api_key')
async def mixlab_llm_api_key_handler(request):
    data = await request.json()
    api_key = data.get('key')

    app_folder = os.path.join(current_path, "app")
    key_file_path = os.path.join(app_folder, "llm_api_key.txt")

    if api_key:
        if not os.path.exists(app_folder):
            os.makedirs(app_folder)
        try:
            with open(key_file_path, 'w') as f:
                f.write(api_key)
            return web.json_response({'message': 'API key saved successfully'})
        except Exception as e:
            return web.json_response({'error': str(e)}, status=500)
    else:
        if os.path.exists(key_file_path):
            try:
                with open(key_file_path, 'r') as f:
                    saved_api_key = f.read().strip()
                return web.json_response({'key': saved_api_key})
            except Exception as e:
                return web.json_response({'error': str(e)}, status=500)
        else:
            return web.json_response({'error': 'No API key provided and no key found in local storage'}, status=400)


@routes.post('/chat/completions')
async def chat_completions(request):
    data = await request.json()
    messages = data.get('messages')
    key=data.get('key')
    api_url=data.get("api_url")
    model_name=data.get("model_name")

    if not api_url:
        api_url="https://api.siliconflow.cn/v1"

    if not model_name:
        model_name="01-ai/Yi-1.5-9B-Chat-16K"

    if not messages:
        return web.json_response({"error": "No messages provided"}, status=400)

    async def generate():
        try:
            headers = {
                'Authorization': f'Bearer {key}',
                'Content-Type': 'application/json'
            }
            payload = {
                'model': model_name,
                'messages': messages,
                'stream': True
            }
            async with aiohttp.ClientSession() as session:
                async with session.post(f'{api_url}/chat/completions', json=payload, headers=headers) as resp:
                    async for line in resp.content:
                        yield line

        except Exception as e:
            yield f"Error: {str(e)}".encode('utf-8') + b"\r\n"

    return web.Response(body=generate(), content_type='text/event-stream')


@routes.get('/mixlab/app')
async def mixlab_app_handler(request):
    html_file = os.path.join(current_path, "webApp/index.html")
    if os.path.exists(html_file):
        with open(html_file, 'r', encoding='utf-8', errors='ignore') as f:
            html_data = f.read()
            return web.Response(text=html_data, content_type='text/html')
    else:
        return web.Response(text="HTML file not found", status=404)

# web app模式独立
@routes.get('/mixlab/app/{filename:.*}')
async def static_file_handler(request):
    filename = request.match_info['filename']
    file_path = os.path.join(current_path, "webApp", filename)
    print(file_path)

    if os.path.exists(file_path) and os.path.isfile(file_path):
        if filename.endswith('.js'):
            content_type = 'application/javascript'
        elif filename.endswith('.css'):
            content_type = 'text/css'
        elif filename.endswith('.html'):
            content_type = 'text/html'
        elif filename.endswith('.svg'):
            content_type = 'image/svg+xml'
        else:
            content_type = 'application/octet-stream'

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            file_data = f.read()
            return web.Response(text=file_data, content_type=content_type)
    else:
        return web.Response(text="File not found", status=404)


@routes.post('/mixlab/workflow')
async def mixlab_workflow_hander(request):
    data = await request.json()
    result={}
    try:
        if 'task' in data:
            if data['task']=='save':
                file_path=save_workflow_json(data['data'])
                result={
                    'status':'success',
                    'file_path':file_path
                }
            elif data['task']=='save_app':
                category=""
                if "category" in data:
                    category=data['category']
                file_path=save_workflow_for_app(data['data'],data['filename'],category)
                result={
                    'status':'success',
                    'file_path':file_path
                }
            elif data['task']=='my_app':
                filename=None
                category=""
                admin=False
                if 'filename' in data:
                    filename=data['filename']
                if 'category' in data:
                    category=data['category']
                if 'admin' in data:
                    admin=data['admin']

                ds=get_my_workflow_for_app(filename,category,admin)
                data=[]
                for json_data in ds:
                    # 不传给前端
                    if 'output' in json_data['data']:
                        del json_data['data']['output']
                    if 'workflow' in json_data['data']:
                        del json_data['data']['workflow']
                    data.append(json_data)

                result={
                    'data':data,
                    'status':'success',
                }
            elif data['task']=='list':
                ds=get_workflows()
                data=[]
                for json_data in ds:
                    # 不传给前端
                    if 'output' in json_data['data']:
                        del json_data['data']['output']
                    if 'workflow' in json_data['data']:
                        del json_data['data']['workflow']
                    data.append(json_data)

                result={
                    'data':data,
                    'status':'success',
                }
    except Exception as e:
            print(e)

    return web.json_response(result)

@routes.post('/mixlab/nodes_map')
async def nodes_map_hander(request):
    data = await request.json()
    result={}
    try:
        result={
            'data':get_nodes_map(),
            'status':'success',
                }
    except Exception as e:
            print(e)

    return web.json_response(result)


@routes.post("/mixlab/folder_paths")
async def get_checkpoints(request):
    data = await request.json()
    t="checkpoints"
    names=[]
    try:
        t=data['type']
        names = folder_paths.get_filename_list(t)
    except Exception as e:
        print('/mixlab/folder_paths',False,e)

    # try:
    #     if data['type']=='llamafile':
    #         names=get_llama_models()
    # except:
    #     print("llamafile none")

    try:
        if data['type']=='rembg':
            names=get_rembg_models(U2NET_HOME)
    except:
        print("rembg none")

    return web.json_response({"names":names,"types":list(folder_paths.folder_names_and_paths.keys())})


@routes.post('/mixlab/rembg')
async def rembg_hander(request):
    data = await request.json()
    model=data['model']
    result={}

    data_base64=remove_base64_prefix(data['base64'])
    image_data = base64.b64decode(data_base64)

    # 创建一个BytesIO对象
    image_stream = io.BytesIO(image_data)

    # 使用PIL Image模块读取图像
    image = Image.open(image_stream)

    if model=='briarmbg':
        _,rgba_images,_=run_briarmbg([image])
    else:
        _,rgba_images,_=run_rembg(model,[image])

    with io.BytesIO() as buf:
        rgba_images[0].save(buf, format='PNG')
        img_bytes = buf.getvalue()
    img_base64 = base64.b64encode(img_bytes).decode('utf-8')

    try:
        result={
            'data':img_base64,
            'model':model,
            'status':'success',
            }
    except Exception as e:
            print(e)

    return web.json_response(result)

# 保存运行结果？暂时去掉
# @routes.post("/mixlab/prompt_result")
# async def post_prompt_result(request):
#     data = await request.json()
#     res=None
#     # print(data)
#     try:
#         action=data['action']
#         if action=='save':
#             result=data['data']
#             res=save_prompt_result(result['prompt_id'],result)
#         elif action=='all':
#             res=get_prompt_result()
#     except Exception as e:
#         print('/mixlab/prompt_result',False,e)

#     return web.json_response({"result":res})

# 种子设置
def random_seed(seed, data):
    max_seed = 4294967295

    for id, value in data.items():
        # print(seed,id)
        if id in seed:
            if 'seed' in value['inputs'] and not isinstance(value['inputs']['seed'], list) and seed[id] in ['increment', 'decrement', 'randomize']:
                value['inputs']['seed'] = round(random.random() * max_seed)

            if 'noise_seed' in value['inputs'] and not isinstance(value['inputs']['noise_seed'], list) and seed[id] in ['increment', 'decrement', 'randomize']:
                value['inputs']['noise_seed'] = round(random.random() * max_seed)

            if value.get('class_type') == "Seed_" and seed[id] in ['increment', 'decrement', 'randomize']:
                value['inputs']['seed'] = round(random.random() * max_seed)
     
        # print('new Seed', value)

    return data


# 运行工作流，代替官方的prompt接口
@routes.post("/mixlab/prompt")
async def mixlab_post_prompt(request):
    p_intance=PromptServer.instance
    logging.info("/mixlab/prompt")
    resp_code = 200
    out_string = ""
    json_data =  await request.json()
    # json_data = p_intance.trigger_on_prompt(json_data)
    # filename,category, client_id ,input
    # workflow 的 filename,category

    # 输入的参数
    input_data=json_data['input'] if "input" in json_data else []
    # 种子
    seed=json_data['seed'] if "seed" in json_data else {}

    try:
        apps=json_data['apps']
    except:
        apps=get_my_workflow_for_app(json_data['filename'],json_data['category'],False)

    prompt=json_data['prompt'] if 'prompt' in json_data else None

    if len(apps)>0:
        # 取到prompt
        prompt=apps[0]['data']['output']
        # logging.info(prompt)
        # 更新input_data到prompt里
        '''
          {
                "inputs": {
                    "number": 512,
                    "min_value": 512,
                    "max_value": 2048,
                    "step": 1
                },
                "class_type": "IntNumber",
                "id": "22"
            },
        '''

        for inp in input_data:
            id=inp['id']
            if prompt[id]['class_type']==inp['class_type']:
                prompt[id]['inputs'].update(inp['inputs'])


    if prompt==None:
        return web.json_response({"error": "no prompt", "node_errors": []}, status=400)
    else:
        # 种子更新
        '''
            "seed": {
                    "45": "randomize",
                    "46": "randomize"
                }
            '''
        json_data["prompt"]=random_seed(seed,prompt)

    # print("#json_data",prompt)
    # 需要把apps处理成 prompt
    # 注意seed的处理

    if "number" in json_data:
        number = float(json_data['number'])
    else:
        number = p_intance.number
        if "front" in json_data:
            if json_data['front']:
                number = -number

        p_intance.number += 1

    if "prompt" in json_data:
        prompt = json_data["prompt"]
        valid = execution.validate_prompt(prompt)
        extra_data = {}
        if "extra_data" in json_data:
            extra_data = json_data["extra_data"]

        if "client_id" in json_data:
            extra_data["client_id"] = json_data["client_id"]
        if valid[0]:
            prompt_id = str(uuid.uuid4())
            outputs_to_execute = valid[2]
            p_intance.prompt_queue.put((number, prompt_id, prompt, extra_data, outputs_to_execute))
            response = {"prompt_id": prompt_id, "number": number, "node_errors": valid[3]}
            return web.json_response(response)
        else:
            logging.warning("invalid prompt: {}".format(valid[1]))
            return web.json_response({"error": valid[1], "node_errors": valid[3]}, status=400)
    else:
        return web.json_response({"error": "no prompt", "node_errors": []}, status=400)


# AR页面
# @routes.get('/mixlab/AR')
async def handle_ar_page(request):
    html_file = os.path.join(current_path, "web/ar.html")
    if os.path.exists(html_file):
        with open(html_file, 'r', encoding='utf-8', errors='ignore') as f:
            html_data = f.read()
            return web.Response(text=html_data, content_type='text/html')
    else:
        return web.Response(text="HTML file not found", status=404)


# 重启服务
@routes.post('/mixlab/re_start')
def re_start(request):
    p_intance=PromptServer.instance
    try:
        p_intance.prompt_queue.set_flag("free_memory", True)
        sys.stdout.close_log()
    except Exception as e:
        pass
    return os.execv(sys.executable, [sys.executable] + sys.argv)

# 状态
@routes.get('/mixlab/status')
def mix_status(request):
    return web.Response(text="running#"+_URL_)

# 导入节点

from .nodes.ImageNode import FaceToMask

# 要导出的所有节点及其名称的字典
# 注意：名称应全局唯一
NODE_CLASS_MAPPINGS = {
    "Rdancer_FaceToMask":FaceToMask,
}

# 一个包含节点友好/可读的标题的字典
NODE_DISPLAY_NAME_MAPPINGS = {
    "Rdancer_FaceToMask":"Face To Mask ♾️Mixlab (Lite 💃)",
}

# web ui的节点功能
WEB_DIRECTORY = "./web"

logging.info('--------------')
logging.info('\033[91m ### Mixlab Nodes: \033[93mLoaded')
# print('\033[91m ### Mixlab Nodes: \033[93mLoaded')



logging.info('\033[93m -------------- \033[0m')

__all__ = ["NODE_CLASS_MAPPINGS", "NODE_DISPLAY_NAME_MAPPINGS"]
