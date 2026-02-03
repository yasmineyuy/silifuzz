#!/bin/bash

# ================= 配置区域 =================
COUNT=20


SNAP_CORPUS_TOOL="${SILIFUZZ_BIN_DIR}/tools/snap_corpus_tool"
SNAP_TOOL="${SILIFUZZ_BIN_DIR}/tools/snap_tool"
TRACE_TOOL="${SILIFUZZ_BIN_DIR}/tracing/trace_tool"
RUNNER="${SILIFUZZ_BIN_DIR}/runner/reading_runner_main_nolibc"

# ================= 外层循环：从 0 到 9 =================
for ((i=0; i<=9; i++)); do
    # 将数字格式化为 5 位数，例如 1 变成 00001
    BATCH_ID=$(printf "%05d" $i)


    # 动态路径配置
    CORPUS_FILE="/tmp/wd/runnable-corpus.${BATCH_ID}"
    OUT_DIR="0116_bin/batch_trace_${BATCH_ID}_bin"
    LOG_DIR="0116_bin/batch_trace_${BATCH_ID}_log"


    # 1. 创建该 Batch 的输出目录
    mkdir -p "${OUT_DIR}"
    mkdir -p "${LOG_DIR}"
    echo "目录已就绪: ${OUT_DIR}"

    # 2. 获取所有 ID
    echo "正在读取 Corpus ${BATCH_ID}..."
    ALL_IDS=$("${SNAP_CORPUS_TOOL}" list_snaps "${CORPUS_FILE}" 2>&1 | grep -E '^[0-9a-fA-F]{40}$')

    if [ -z "$ALL_IDS" ]; then
        echo "错误: Corpus ${BATCH_ID} 未能读取到 ID，跳过。"
        continue
    fi

    # 随机选择
    SELECTED_IDS=$(echo "$ALL_IDS" | shuf -n "${COUNT}")

    # 3. 内层循环：处理具体的 ID
    INDEX=1
    for ID in $SELECTED_IDS; do
        SHORT_ID=${ID:0:8}
        TEMP_PB="${OUT_DIR}/temp_${ID}.pb"
        BIN_FILE="${OUT_DIR}/op_${INDEX}.bin"
        LOG_FILE="${LOG_DIR}/op_${INDEX}.log"

        echo "  [Batch ${BATCH_ID} | ${INDEX}/${COUNT}] 处理 ID: ${SHORT_ID}..."

        # 步骤 A: Extract
        "${SNAP_CORPUS_TOOL}" extract "${CORPUS_FILE}" "${ID}" "${TEMP_PB}" 2>/dev/null
        
        if [ ! -f "${TEMP_PB}" ]; then
            echo "    -> 提取失败，跳过。"
            continue
        fi

        # 步骤 B: Get Instructions
        "${SNAP_TOOL}" --runner="${RUNNER}" get_instructions "${TEMP_PB}" > "${BIN_FILE}" 2>/dev/null

        # 步骤 C: Trace
        if [ -s "${BIN_FILE}" ]; then
            "${TRACE_TOOL}" --runner="${RUNNER}" print --snippet="${BIN_FILE}" --arch=x86_64 --tracer=native > "${LOG_FILE}" 2>/dev/null
        else
            echo "    -> Bin 生成失败"
        fi

        # 清理
        rm -f "${TEMP_PB}"

        ((INDEX++))
    done

    echo "Batch ${BATCH_ID} 完成。"
    echo ""
done

echo "=================================================="
echo "所有任务 (00000 - 00009) 执行完毕！"