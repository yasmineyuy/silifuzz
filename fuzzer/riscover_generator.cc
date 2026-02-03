// silifuzz/fuzzer/riscover_generator.cc
#include "./fuzzer/riscover_generator.h"

#include <cstring>  // for std::memset
#include <limits>
#include <vector>

namespace silifuzz {

namespace {

// --- RISCover 策略配置 ---

// RISCover 策略：限制池 (制造 RAW 依赖)
// 对应论文中的 "Restricted Pool"
const std::vector<xed_reg_enum_t> kRestrictedPool = {
    XED_REG_RAX, XED_REG_RCX, XED_REG_RDX, XED_REG_RBX, XED_REG_RSI};

// 全集池 (覆盖率)
// 排除 RSP/RBP 防止栈崩溃
const std::vector<xed_reg_enum_t> kFullPool = {
    XED_REG_RAX, XED_REG_RCX, XED_REG_RDX, XED_REG_RBX, XED_REG_RSI,
    XED_REG_RDI, XED_REG_R8,  XED_REG_R9,  XED_REG_R10, XED_REG_R11,
    XED_REG_R12, XED_REG_R13, XED_REG_R14, XED_REG_RIP};

// 基础算术指令集 (可以根据需要扩展)
const std::vector<xed_iclass_enum_t> kSupportedIclass = {
    XED_ICLASS_ADD, XED_ICLASS_SUB,      XED_ICLASS_XOR,      XED_ICLASS_AND,
    XED_ICLASS_OR,  XED_ICLASS_MOV,      XED_ICLASS_ADC,      XED_ICLASS_SBB,
    XED_ICLASS_CMP, XED_ICLASS_CALL_FAR, XED_ICLASS_CALL_NEAR};

// --- XED 操作数构造辅助函数 ---

xed_encoder_operand_t MakeRegOperand(xed_reg_enum_t reg) {
  xed_encoder_operand_t op;
  std::memset(&op, 0, sizeof(op));
  op.type = XED_ENCODER_OPERAND_TYPE_REG;
  op.u.reg = reg;
  return op;
}

xed_encoder_operand_t MakeImmOperand(uint64_t imm, unsigned int width_bits) {
  xed_encoder_operand_t op;
  std::memset(&op, 0, sizeof(op));
  op.type = XED_ENCODER_OPERAND_TYPE_IMM0;
  op.u.imm0 = imm;
  op.width_bits = width_bits;
  return op;
}

}  // namespace

// --- RiscoverGenerator 实现 ---

xed_reg_enum_t RiscoverGenerator::SelectRegister(Rng& rng) {
  // 1/6 概率完全随机 (Escape to full pool)
  if (std::uniform_int_distribution<>(0, 5)(rng) == 0) {
    std::uniform_int_distribution<> dist(0, kFullPool.size() - 1);
    return kFullPool[dist(rng)];
  }
  // 5/6 概率限制在小池子 (Force dependency)
  std::uniform_int_distribution<> dist(0, kRestrictedPool.size() - 1);
  return kRestrictedPool[dist(rng)];
}

uint64_t RiscoverGenerator::SelectImmediate(Rng& rng, unsigned int width_bits) {
  uint64_t mask = (width_bits == 64) ? ~0ULL : (1ULL << width_bits) - 1;

  // 20% 概率纯随机 (Random Mode)
  if (std::uniform_int_distribution<>(0, 4)(rng) == 0) {
    std::uniform_int_distribution<uint64_t> dist;
    return dist(rng) & mask;
  }

  // 80% 概率特殊值 (Corner Cases)
  std::vector<uint64_t> corners = {0, 1};
  corners.push_back(mask);             // -1 (all ones)
  corners.push_back(mask >> 1);        // MAX_INT
  corners.push_back((mask >> 1) + 1);  // MIN_INT (sign bit set)

  std::uniform_int_distribution<> dist(0, corners.size() - 1);
  return corners[dist(rng)];
}

bool RiscoverGenerator::GenerateInstruction(Rng& rng, uint8_t* buf,
                                            size_t& len) {
  std::uniform_int_distribution<> iclass_dist(0, kSupportedIclass.size() - 1);
  xed_iclass_enum_t iclass = kSupportedIclass[iclass_dist(rng)];

  // 随机选择 32位 或 64位 操作
  unsigned int width = std::uniform_int_distribution<>(0, 1)(rng) ? 64 : 32;

  // 50% 概率 Reg-Reg, 50% 概率 Reg-Imm
  if (std::uniform_int_distribution<>(0, 1)(rng)) {
    return GenerateRegReg(rng, iclass, width, buf, len);
  } else {
    return GenerateRegImm(rng, iclass, width, buf, len);
  }
}

bool RiscoverGenerator::GenerateRegReg(Rng& rng, xed_iclass_enum_t iclass,
                                       unsigned int width, uint8_t* buf,
                                       size_t& len) {
  InstructionBuilder builder(iclass, width);
  builder.AddOperands(MakeRegOperand(SelectRegister(rng)),  // REG0 (Dest)
                      MakeRegOperand(SelectRegister(rng))   // REG1 (Source)
  );
  return builder.Encode(buf, len);
}

bool RiscoverGenerator::GenerateRegImm(Rng& rng, xed_iclass_enum_t iclass,
                                       unsigned int width, uint8_t* buf,
                                       size_t& len) {
  InstructionBuilder builder(iclass, width);
  builder.AddOperands(
      MakeRegOperand(SelectRegister(rng)),                // REG0 (Dest)
      MakeImmOperand(SelectImmediate(rng, width), width)  // IMM0 (Source)
  );
  return builder.Encode(buf, len);
}

}  // namespace silifuzz