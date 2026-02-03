// Copyright 2023 The Silifuzz Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>
#include <random>

#include "absl/log/check.h"
#include "./fuzzer/program.h"
#include "./fuzzer/program_arch.h"
#include "./instruction/xed_util.h"
#include "./util/arch.h"

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

namespace silifuzz {

namespace {

// Filter out problematic instructions.
bool AcceptInstruction(const xed_decoded_inst_t& xedd) {
  const xed_inst_t* instruction = xed_decoded_inst_inst(&xedd);
  return InstructionIsAllowedInRunner(instruction);
}

InstructionDisplacementInfo GetDirectBranchInfo(
    const xed_decoded_inst_t& xedd, int64_t displacement_fixup_limit) {
  InstructionDisplacementInfo info{};
  if (xed_decoded_inst_get_branch_displacement_width(&xedd) > 0) {
    int64_t displacement = xed_decoded_inst_get_branch_displacement(&xedd) +
                           xed_decoded_inst_get_length(&xedd);
    if (DisplacementWithinFixupLimit(displacement, displacement_fixup_limit)) {
      info.encoded_byte_displacement = displacement;
    }
  }
  return info;
}

void ReencodeInternal(const xed_state_t& dstate, Instruction<X86_64>& insn) {
  xed_decoded_inst_t xedd;
  xed_decoded_inst_zero_set_mode(&xedd, &dstate);

  CHECK_EQ(xed_decode(&xedd, insn.encoded.data(), insn.encoded.size()),
           XED_ERROR_NONE);
  CHECK_EQ(xed_decoded_inst_get_length(&xedd), insn.encoded.size());

  uint64_t displacement_width =
      xed_decoded_inst_get_branch_displacement_width(&xedd);
  CHECK_GT(displacement_width, 0);

  int64_t new_displacement = insn.direct_branch.encoded_byte_displacement -
                             xed_decoded_inst_get_length(&xedd);

  xed_encoder_request_init_from_decode(&xedd);
  xed_decoded_inst_set_branch_displacement(&xedd, new_displacement,
                                           displacement_width);

  InstructionByteBuffer<X86_64> ibuf;
  unsigned int actual_len = 0;
  xed_error_enum_t res = xed_encode(&xedd, ibuf, sizeof(ibuf), &actual_len);
  CHECK_EQ(res, XED_ERROR_NONE);
  insn.encoded.Copy(ibuf, actual_len);
}

// ========================================================================================
// [RISCover Strategy Implementation]
// ========================================================================================

// 强制使用的受限寄存器集合 (x0-x5)
const xed_reg_enum_t kRestrictedRegs64[] = {XED_REG_RAX, XED_REG_RBX, XED_REG_RCX, XED_REG_RDX, XED_REG_RSI, XED_REG_RDI};
const xed_reg_enum_t kRestrictedRegs32[] = {XED_REG_EAX, XED_REG_EBX, XED_REG_ECX, XED_REG_EDX, XED_REG_ESI, XED_REG_EDI};
const xed_reg_enum_t kRestrictedRegs16[] = {XED_REG_AX, XED_REG_BX, XED_REG_CX, XED_REG_DX, XED_REG_SI, XED_REG_DI};
const xed_reg_enum_t kRestrictedRegs8[] =  {XED_REG_AL, XED_REG_BL, XED_REG_CL, XED_REG_DL, XED_REG_SIL, XED_REG_DIL};

xed_reg_enum_t GetRestrictedReg(xed_reg_enum_t old_reg, MutatorRng& rng) {
    xed_uint_t width = xed_get_register_width_bits64(old_reg);
    size_t idx = std::uniform_int_distribution<size_t>(0, 5)(rng);

    switch (width) {
        case 64: return kRestrictedRegs64[idx];
        case 32: return kRestrictedRegs32[idx];
        case 16: return kRestrictedRegs16[idx];
        case 8:  return kRestrictedRegs8[idx];
        default: return old_reg;
    }
}

uint64_t GetInterestingImmediate(uint64_t current_val, uint32_t width_bits, MutatorRng& rng) {
    if (std::bernoulli_distribution(0.2)(rng)) return current_val;

    static const uint64_t kInterestingValues[] = {
        0, 1, 2, 
        std::numeric_limits<uint64_t>::max(),
        std::numeric_limits<uint64_t>::max() - 1,
        0x8000000000000000ULL, 
        0x7FFFFFFFFFFFFFFFULL,
        0xAAAAAAAAAAAAAAAAULL,
        0x5555555555555555ULL,
    };
    
    // Size is 9
    uint64_t val = kInterestingValues[std::uniform_int_distribution<size_t>(0, 8)(rng)]; 

    if (width_bits < 64) {
        uint64_t mask = (1ULL << width_bits) - 1;
        if (std::bernoulli_distribution(0.5)(rng)) {
             const uint64_t kWidthSpecific[] = {
                0, 1, mask, mask >> 1, 1ULL << (width_bits - 1)
             };
             // Size is 5
             return kWidthSpecific[std::uniform_int_distribution<size_t>(0, 4)(rng)];
        }
        return val & mask;
    }
    return val;
}

}  // namespace

template <>
void ArchSpecificInit<X86_64>() {
  InitXedIfNeeded();
}

template <>
bool InstructionFromBytes(const uint8_t* bytes, size_t num_bytes,
                          Instruction<X86_64>& instruction,
                          const InstructionConfig& config,
                          bool must_decode_everything) {
  instruction.encoded.Clear();
  xed_decoded_inst_t xedd;
  xed_decoded_inst_zero(&xedd);
  xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  if (xed_decode(&xedd, bytes, num_bytes) != XED_ERROR_NONE) return false;
  size_t decoded_length = xed_decoded_inst_get_length(&xedd);

  instruction.encoded.Copy(bytes, decoded_length);
  instruction.direct_branch = GetDirectBranchInfo(xedd, config.displacement_fixup_limit);

  if (must_decode_everything && decoded_length != num_bytes) return false;
  if (config.filter) {
    if (!AcceptInstruction(xedd)) return false;
  }
  return true;
}

template <>
bool TryToReencodeInstructionDisplacements(Instruction<X86_64>& insn) {
  CHECK(insn.direct_branch.valid());
  xed_state_t dstate;
  xed_state_init2(&dstate, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  size_t original_size = insn.encoded.size();
  ReencodeInternal(dstate, insn);
  size_t canonical_size = insn.encoded.size();
  if (original_size != canonical_size) {
    ReencodeInternal(dstate, insn);
    CHECK_EQ(insn.encoded.size(), canonical_size);
  }

  xed_decoded_inst_t xedd;
  xed_decoded_inst_zero_set_mode(&xedd, &dstate);
  CHECK_EQ(xed_decode(&xedd, insn.encoded.data(), insn.encoded.size()), XED_ERROR_NONE);
  CHECK_EQ(xed_decoded_inst_get_length(&xedd), insn.encoded.size());

  if (xed_decoded_inst_get_branch_displacement(&xedd) +
          xed_decoded_inst_get_length(&xedd) !=
      insn.direct_branch.encoded_byte_displacement)
    return false;

  return true;
}

// [External Interface Implementation]
bool SmartMutateX86Instruction(const uint8_t* bytes, size_t len, 
                               InstructionByteBuffer<X86_64>& out_buffer, size_t& out_len, 
                               MutatorRng& rng) {
    xed_decoded_inst_t xedd;
    xed_state_t dstate;

    // Correctly initialize XED State
    xed_state_init2(&dstate, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
    xed_decoded_inst_zero_set_mode(&xedd, &dstate); 
    
    if (xed_decode(&xedd, bytes, len) != XED_ERROR_NONE) return false;

    // Convert to Encoder Request
    xed_encoder_request_init_from_decode(&xedd);
    bool changed = false;

    // Get static instruction info to iterate operands
    const xed_inst_t* inst = xed_decoded_inst_inst(&xedd);
    unsigned int nops = xed_inst_noperands(inst);

    // 1. Register Replacement (Dependency)
    for (unsigned int i = 0; i < nops; ++i) {
        const xed_operand_t* op = xed_inst_operand(inst, i);
        xed_operand_enum_t op_name = xed_operand_name(op);
        
        if (xed_operand_is_register(op_name)) {
            // Retrieve current register from the decoded structure
            xed_reg_enum_t reg = xed_decoded_inst_get_reg(&xedd, op_name);
            
            // Only replace General Purpose Registers (GPR)
            if (xed_reg_class(reg) == XED_REG_CLASS_GPR) {
                if (std::bernoulli_distribution(0.5)(rng)) {
                    xed_reg_enum_t new_reg = GetRestrictedReg(reg, rng);
                    if (new_reg != reg) {
                        // FIX: Use the standard API to set the register
                        xed_encoder_request_set_reg(&xedd, op_name, new_reg);
                        changed = true;
                    }
                }
            }
        }
    }

    // 2. Immediate Replacement (Boundary Values)
    if (xed_decoded_inst_get_immediate_width_bits(&xedd) > 0) {
        if (std::bernoulli_distribution(0.8)(rng)) {
            uint64_t imm = xed_decoded_inst_get_unsigned_immediate(&xedd);
            uint32_t width = xed_decoded_inst_get_immediate_width_bits(&xedd);
            uint64_t new_imm = GetInterestingImmediate(imm, width, rng);
            
            if (new_imm != imm) {
                xed_encoder_request_set_uimm0_bits(&xedd, new_imm, width);
                changed = true;
            }
        }
    }

    // Attempt to encode regardless of 'changed' to ensure we return valid bytes 
    // (sometimes re-encoding normalizes the instruction even if we didn't touch it)
    unsigned int encoded_len = 0;
    xed_error_enum_t err = xed_encode(&xedd, out_buffer, sizeof(out_buffer), &encoded_len);
    
    if (err != XED_ERROR_NONE) return false;
    
    out_len = encoded_len;
    return true; // Return true as long as we produced a valid instruction
}

}  // namespace silifuzz