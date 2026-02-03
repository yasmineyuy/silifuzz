// silifuzz/fuzzer/riscover_generator.h
#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_RISCOVER_GENERATOR_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_RISCOVER_GENERATOR_H_

#include <cstddef>
#include <cstdint>
#include <random>
#include <vector>

#include "./instruction/xed_util.h"
#include "./util/arch.h"

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

namespace silifuzz {

// 实现了 RISCover 论文中的加权随机生成策略
class RiscoverGenerator {
 public:
  // 使用外部传入的 RNG (Silifuzz 的 MutatorRng)
  using Rng = std::mt19937_64;

  // 尝试生成一条 x86 指令
  // buf: 输出缓冲区
  // len: 输入 buffer 大小，输出实际指令长度
  bool GenerateInstruction(Rng& rng, uint8_t* buf, size_t& len);

 private:
  // --- 核心策略 1: 寄存器选择 ---
  // 83% 概率从限制池(x0-x4)选，17% 概率从全集选
  xed_reg_enum_t SelectRegister(Rng& rng);

  // --- 核心策略 2: 立即数选择 ---
  // 80% 概率选特殊值(0, -1, MAX)，20% 概率纯随机
  uint64_t SelectImmediate(Rng& rng, unsigned int width_bits);

  // --- 辅助生成函数 ---
  bool GenerateRegReg(Rng& rng, xed_iclass_enum_t iclass, unsigned int width,
                      uint8_t* buf, size_t& len);
  bool GenerateRegImm(Rng& rng, xed_iclass_enum_t iclass, unsigned int width,
                      uint8_t* buf, size_t& len);
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_RISCOVER_GENERATOR_H_