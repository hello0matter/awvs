import requests
import urllib3
import concurrent.futures

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

API_KEY = "1986ad8c0a5b3df4d7028d5f3c06e936cb4217b974a8b4f40b1086d31d7e8869e"
BASE_URL = "https://localhost:3443/api/v1"

headers = {
    "X-Auth": API_KEY,
    "Content-Type": "application/json"
}

# 专门处理中止请求的函数（供线程池调用）
def abort_task(scan_id, status):
    abort_url = f"{BASE_URL}/scans/{scan_id}/abort"
    try:
        res = requests.post(abort_url, headers=headers, verify=False)
        if res.status_code == 204:
            print(f"[+] 极速中止: {scan_id} | 原状态: {status}")
            return True
    except Exception as e:
        print(f"[-] 请求异常: {scan_id} | 错误: {e}")
    return False

def stop_all_scans():
    try:
        cursor = 0
        page = 1
        total_aborted = 0

        while True:
            list_url = f"{BASE_URL}/scans?l=100&c={cursor}"
            print(f"\n[*] 正在拉取第 {page} 页...")
            
            response = requests.get(list_url, headers=headers, verify=False)
            if response.status_code != 200:
                break

            scans = response.json().get('scans', [])
            if not scans:
                print(f"[*] 全部页码遍历完毕。")
                break

            tasks_to_abort = []
            for scan in scans:
                scan_id = scan.get('scan_id')
                current_session = scan.get('current_session', {})
                status = current_session.get('status') or scan.get('status')
                
                if status in ['processing', 'queued', 'scheduled', 'starting']:
                    tasks_to_abort.append((scan_id, status))

            # 【核心加速区】：开启 20 个并发线程同时发送中止请求
            if tasks_to_abort:
                print(f"[*] 发现 {len(tasks_to_abort)} 个任务，启动多线程并发清理...")
                with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                    # 将任务丢进线程池
                    futures = [executor.submit(abort_task, sid, st) for sid, st in tasks_to_abort]
                    # 统计成功数量
                    for future in concurrent.futures.as_completed(futures):
                        if future.result():
                            total_aborted += 1

            cursor += 100
            page += 1

        print(f"\n[!] 闪电清理完成！共干掉 {total_aborted} 个任务。")

    except Exception as e:
        print(f"[X] 出错: {str(e)}")

if __name__ == "__main__":
    stop_all_scans()

#UPDATE scan_session_jobs SET abort_requested = true WHERE status IN ('processing', 'queued');