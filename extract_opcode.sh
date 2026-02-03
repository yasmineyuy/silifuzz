#!/bin/bash

# ================= 配置区域 =================
# 你的根目录
BASE_DIR="0116_bin"

# 循环范围：根据你说的9个文件夹，这里设为 0 到 8
# 如果你有更多（比如到00009），请把 8 改成 9
START_BATCH=0
END_BATCH=9

# ================= 脚本逻辑 =================

for ((i=START_BATCH; i<=END_BATCH; i++)); do
    # 格式化 ID，例如 0 -> 00000
    BATCH_ID=$(printf "%05d" $i)
    
    # 定义源目录和目标目录
    SRC_DIR="${BASE_DIR}/batch_trace_${BATCH_ID}_bin"
    DST_DIR="${BASE_DIR}/batch_trace_${BATCH_ID}_opcode"

    # 检查源目录是否存在
    if [ ! -d "${SRC_DIR}" ]; then
        echo "警告: 目录 ${SRC_DIR} 不存在，跳过..."
        continue
    fi

    # 创建目标目录
    mkdir -p "${DST_DIR}"
    echo "正在处理 Batch: ${BATCH_ID} -> ${DST_DIR}"

    # 遍历 bin 文件
    # 使用 find 确保即使目录为空也不会报错，且处理路径更安全
    find "${SRC_DIR}" -maxdepth 1 -name "*.bin" | while read BIN_FILE; do
        # 获取文件名 (例如 op_1.bin) 和 基础名 (op_1)
        FILENAME=$(basename "${BIN_FILE}")
        BASENAME="${FILENAME%.*}"
        
        # 定义输出文件 (例如 op_1.txt)
        OUT_FILE="${DST_DIR}/${BASENAME}.txt"

        # === 核心转换命令 ===
        # od -An     : 不输出地址偏移量 (去掉最左边的数字)
        # -v         :啰嗦模式 (不要把重复行显示为 *)
        # -t x1      : 输出单字节十六进制
        # tr -s ' '  : 把连续的空格压缩成一个空格
        # sed 's/^ //' : 去掉每行开头可能多余的一个空格
        od -An -v -t x1 "${BIN_FILE}" | tr -s ' ' | sed 's/^ //' > "${OUT_FILE}"

    done
done

echo "----------------------------------------"
echo "全部转换完成！"
echo "Opcode 文件保存在 *_opcode 文件夹内。"
