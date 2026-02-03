#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_RISCOVER_GENERATOR_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_RISCOVER_GENERATOR_H_

#include <cstddef>
#include <cstdint>
#include <random>
#include <vector>

// 注意：这里路径可能需要根据你的实际情况调整，如果找不到头文件，
// 请检查 BUILD 文件中的 deps 是否正确包含了 "//silifuzz/instruction:xed_util"
#include "./instruction/xed_util.h"
#include "./util/arch.h"

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

namespace silifuzz {

class RiscoverGenerator {
 public:
  // [修改点] 将 mt19937 改为 mt19937_64，以匹配 MutatorRng
  using Rng = std::mt19937_64;

  bool GenerateInstruction(Rng& rng, uint8_t* buf, size_t& len);

 private:
  xed_reg_enum_t SelectRegister(Rng& rng);
  uint64_t SelectImmediate(Rng& rng, unsigned int width_bits);

  bool GenerateRegReg(Rng& rng, xed_iclass_enum_t iclass, unsigned int width,
                      uint8_t* buf, size_t& len);
  bool GenerateRegImm(Rng& rng, xed_iclass_enum_t iclass, unsigned int width,
                      uint8_t* buf, size_t& len);
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_RISCOVER_GENERATOR_H_