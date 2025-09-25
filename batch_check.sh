#!/bin/bash

# 脚本：批量执行域名的xdns扫描
# 从domains文件夹中读取所有.txt文件，逐个执行xdns命令

echo "开始批量执行域名扫描..."

# 检查必要文件是否存在
if [ ! -f "xdns" ]; then
    echo "错误: xdns 可执行文件不存在"
    exit 1
fi

if [ ! -f "dns_resolver_0913.txt" ]; then
    echo "错误: dns_resolver_0913.txt 文件不存在"
    exit 1
fi

if [ ! -d "domains" ]; then
    echo "错误: domains 文件夹不存在"
    exit 1
fi

# 创建results目录
if [ ! -d "results" ]; then
    echo "创建results目录..."
    mkdir -p results
fi

# 获取domains文件夹中所有.txt文件
echo "扫描domains文件夹中的.txt文件..."
domain_files=($(find domains -name "*.txt" -type f | sort))

if [ ${#domain_files[@]} -eq 0 ]; then
    echo "错误: domains文件夹中没有找到.txt文件"
    exit 1
fi

echo "找到 ${#domain_files[@]} 个域名文件"

# 显示将要处理的文件列表
echo "将要处理的文件:"
for file in "${domain_files[@]}"; do
    echo "  - $file"
done

# 询问用户是否继续
read -p "是否继续执行扫描? (y/N): " confirm
if [[ ! $confirm =~ ^[Yy]$ ]]; then
    echo "用户取消操作"
    exit 0
fi

# 记录开始时间
start_time=$(date)
echo "开始时间: $start_time"

# 为每个域名文件执行xdns命令
success_count=0
error_count=0
total_files=${#domain_files[@]}

for i in "${!domain_files[@]}"; do
    domain_file="${domain_files[$i]}"
    
    # 从文件路径提取文件名（不含路径和扩展名）
    filename=$(basename "$domain_file" .txt)
    output_file="results/result_${filename}.txt"
    
    current_num=$((i + 1))
    
    echo ""
    echo "========================================="
    echo "[$current_num/$total_files] 正在处理文件: $domain_file"
    echo "输出文件: $output_file"
    echo "========================================="
    
    # 执行xdns命令
    sudo ./xdns -domainlist "$domain_file" \
                -dnsfile dns_resolver_0913.txt \
                -iface ens34 \
                -srcip 202.112.47.150 \
                -srcmac 00:0c:29:95:4c:5f \
                -gtwmac ac:74:09:b8:c3:00 \
                -rate 30000 \
                -out "$output_file"
    
    # 检查命令执行结果
    if [ $? -eq 0 ]; then
        echo "✓ $domain_file 扫描完成"
        success_count=$((success_count + 1))
    else
        echo "✗ $domain_file 扫描失败"
        error_count=$((error_count + 1))
        
        # 询问是否继续
        read -p "是否继续下一个文件? (Y/n): " continue_scan
        if [[ $continue_scan =~ ^[Nn]$ ]]; then
            echo "用户选择停止扫描"
            break
        fi
    fi
    
    echo "当前进度: 成功 $success_count, 失败 $error_count, 剩余 $((total_files - current_num))"
done

# 记录结束时间和统计信息
end_time=$(date)
echo ""
echo "========================================="
echo "扫描完成!"
echo "开始时间: $start_time"
echo "结束时间: $end_time"
echo "总文件数: $total_files"
echo "成功扫描: $success_count 个文件"
echo "失败扫描: $error_count 个文件"
echo "结果文件保存在: results/ 目录"
echo "========================================="

# 显示results目录内容
if [ $success_count -gt 0 ]; then
    echo ""
    echo "生成的结果文件:"
    ls -la results/
fi