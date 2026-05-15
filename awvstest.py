import pandas as pd
import os
import math
import argparse

def generate_awvs_csv(input_file, output_dir="awvs_targets_output", chunk_size=500):
    print(f"[*] 正在读取文件: {input_file}")
    
    # 获取文件后缀
    ext = os.path.splitext(input_file)[1].lower()
    urls = []
    
    try:
        if ext == '.txt':
            with open(input_file, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f.readlines() if line.strip()]
        elif ext == '.csv':
            df = pd.read_csv(input_file, header=None)
            urls = df.iloc[:, 0].dropna().astype(str).tolist()
        elif ext in ['.xlsx', '.xls']:
            df = pd.read_excel(input_file, header=None)
            urls = df.iloc[:, 0].dropna().astype(str).tolist()
        else:
            print("[-] 不支持的文件格式，请提供 .txt, .csv 或 .xlsx 文件")
            return
    except Exception as e:
        print(f"[-] 读取文件时出错: {e}")
        return

    # 去重并清理空行（保持原有顺序）
    seen = set()
    clean_urls = []
    for url in urls:
        u = url.strip()
        if u and u not in seen:
            clean_urls.append(u)
            seen.add(u)

    total_urls = len(clean_urls)
    print(f"[*] 提取到 {total_urls} 个有效且不重复的 URL。")

    if total_urls == 0:
        print("[-] 没有提取到有效的 URL，程序结束。")
        return

    # 创建输出文件夹
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # 按指定大小切割
    total_parts = math.ceil(total_urls / chunk_size)
    base_name = os.path.splitext(os.path.basename(input_file))[0]
    
    global_counter = 1 # 描述字段：从 1 开始全局递增

    for i in range(total_parts):
        part_urls = clean_urls[i * chunk_size : (i + 1) * chunk_size]
        output_file = os.path.join(output_dir, f"{base_name}_awvs_part{i+1}.csv")

        with open(output_file, 'w', encoding='utf-8') as f:
            for url in part_urls:
                f.write(f"{url},{global_counter}\n")
                global_counter += 1

        print(f"[+] 已生成: {output_file} (包含 {len(part_urls)} 个目标)")

    print(f"\n[√] 处理完成！所有切割好的文件已保存在 '{output_dir}' 文件夹下。")

if __name__ == "__main__":
    # 设置命令行参数解析
    parser = argparse.ArgumentParser(description="AWVS 目标批量导入 CSV 生成工具")
    
    # 必填参数：输入文件
    parser.add_argument("-i", "--input", required=True, help="输入文件路径 (支持 .txt, .csv, .xlsx)")
    
    # 可选参数：每个文件的数量（默认500）
    parser.add_argument("-c", "--chunk", type=int, default=500, help="每个分割文件包含的 URL 数量 (默认: 500)")
    
    # 可选参数：输出目录名
    parser.add_argument("-o", "--output", default="awvs_targets_output", help="输出文件夹名称 (默认: awvs_targets_output)")

    # 解析参数
    args = parser.parse_args()

    # 检查输入文件是否存在
    if os.path.exists(args.input):
        generate_awvs_csv(args.input, args.output, args.chunk)
    else:
        print(f"[-] 错误: 找不到文件 '{args.input}'，请检查路径是否正确。")