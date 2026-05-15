import requests
import urllib3

# 禁用自签名证书的警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- 你的 AWVS 配置 ---
API_KEY = "1986ad8c0a5b3df4d7028d5f3c06e936cb4217b974a8b4f40b1086d31d7e8869e"
BASE_URL = "https://localhost:3443/api/v1"
HEADERS = {
    "X-Auth": API_KEY,
    "Content-Type": "application/json"
}

def get_current_workers():
    """获取当前的 Worker 列表及状态"""
    try:
        res = requests.get(f"{BASE_URL}/workers", headers=HEADERS, verify=False)
        if res.status_code == 200:
            return res.json().get("workers", [])
        else:
            print(f"[-] 获取 Worker 列表失败，状态码: {res.status_code}")
            return None
    except Exception as e:
        print(f"[X] 请求出错: {e}")
        return None

def update_worker_limit(worker_id, new_limit):
    """修改指定 Worker 的并发上限"""
    try:
        url = f"{BASE_URL}/workers/{worker_id}"
        payload = {"max_concurrent_scans": new_limit}
        
        res = requests.patch(url, json=payload, headers=HEADERS, verify=False)
        if res.status_code == 204:
            print(f"[+] 成功将引擎并发数修改为: {new_limit}")
            return True
        else:
            print(f"[-] 修改失败，状态码: {res.status_code}")
            return False
    except Exception as e:
        print(f"[X] 修改时出错: {e}")
        return False

def main():
    print("=" * 50)
    print(" AWVS 引擎并发数动态修改工具 (API 方式)")
    print("=" * 50)
    
    workers = get_current_workers()
    if not workers:
        print("未能找到可用的扫描引擎，请检查 API Key 或 AWVS 服务是否正常。")
        return

    # 通常只有一个本地引擎
    target_worker = workers[0]
    worker_id = target_worker.get("worker_id")
    worker_name = target_worker.get("name", "Local Engine")
    current_limit = target_worker.get("max_concurrent_scans")
    
    print(f"\n[*] 当前引擎名称: {worker_name}")
    print(f"[*] 当前最大并发数: {current_limit}")
    
    while True:
        try:
            # 交互式输入新的并发数
            user_input = input("\n[?] 请输入您想要设置的新的最大并发数 (建议 5-10，输入 'q' 退出): ")
            
            if user_input.lower() == 'q':
                print("退出脚本。")
                break
                
            new_limit = int(user_input)
            
            if new_limit <= 0:
                print("[-] 并发数必须大于 0！")
                continue
            
            if new_limit > 50:
                 confirm = input("[!] 警告：设置超过 50 个并发可能导致机器死机。确定要继续吗？(y/n): ")
                 if confirm.lower() != 'y':
                     continue
                     
            # 调用修改函数
            if update_worker_limit(worker_id, new_limit):
                print("\n[!] 修改指令已发送！")
                print("==================================================================")
                print(" 极其重要：由于 supervisor 进程可能已锁死之前的状态，")
                print(" 请务必去 Windows '服务' (services.msc) 中，右键重新启动 'Acunetix' 服务，")
                print(" 新的并发数才会真正生效，并且僵尸进程会被彻底清理！")
                print("==================================================================")
                break
                
        except ValueError:
            print("[-] 输入无效，请输入一个整数。")

if __name__ == "__main__":
    main()