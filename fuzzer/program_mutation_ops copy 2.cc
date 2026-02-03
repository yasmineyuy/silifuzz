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

#include "./fuzzer/program_mutation_ops.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <numeric>
#include <random>

#include "./fuzzer/program.h"
#include "./fuzzer/program_arch.h"
#include "./util/arch.h"  // IWYU pragma: keep
#include "absl/log/check.h"

namespace silifuzz {

namespace {

// Copied from bitops.h because there's no good place to put it, yet.
template <size_t N>
static constexpr auto BestIntType() {
  if constexpr (N % sizeof(uint64_t) == 0) {
    return uint64_t{};
  } else if constexpr (N % sizeof(uint32_t) == 0) {
    return uint32_t{};
  } else if constexpr (N % sizeof(uint16_t) == 0) {
    return uint16_t{};
  } else {
    return uint8_t{};
  }
}

template <size_t N>
void RandomizeBuffer(MutatorRng& rng, uint8_t (&buffer)[N]) {
  using ResultType = MutatorRng::result_type;

  static_assert(MutatorRng::min() == std::numeric_limits<ResultType>::min(),
                "RNG is expected to produce the full range of values.");
  static_assert(MutatorRng::max() == std::numeric_limits<ResultType>::max(),
                "RNG is expected to produce the full range of values.");

  // Determine the largest integral type that is a multiple of the buffer size
  // as well as the RNG result size.
  using Granularity = decltype(BestIntType<std::gcd(N, sizeof(ResultType))>());

  static_assert(sizeof(buffer) % sizeof(Granularity) == 0,
                "Byte buffer should be a multiple of granularity.");
  static_assert(sizeof(ResultType) % sizeof(Granularity) == 0,
                "ResultType should be a multiple of granularity.");

  Granularity* word_view = reinterpret_cast<Granularity*>(buffer);
  for (size_t i = 0; i < sizeof(buffer) / sizeof(Granularity); ++i) {
    *word_view++ = (Granularity)rng();
  }
}

void CopyOrRandomizeInstructionDisplacementBoundary(
    MutatorRng& rng, const InstructionDisplacementInfo& original,
    InstructionDisplacementInfo& mutated, size_t num_boundaries) {
  // Does this displacement need fixup?
  if (mutated.valid()) {
    if (original.valid() && mutated.encoded_byte_displacement ==
                                original.encoded_byte_displacement) {
      // Since the byte displacement is unchanged, preserve the boundary.
      // The boundary may be out of sync with the encoded byte displacement,
      // so we don't worry about the exact value of the byte displacement,
      // we're only observing that the mutation did not change it.
      mutated.instruction_boundary = original.instruction_boundary;
    } else {
      // If this was a newly discovered displacement, randomize the boundary.
      // If the displacement was mutated, randomize the boundary.
      // Trying to derive the boundary from the mutated displacement has a
      // number of pitfalls that we avoid with a complete re-randomization.
      RandomizeInstructionDisplacementBoundary(rng, mutated, num_boundaries);
    }
  }
}

void ShiftOrRandomizeInstructionDisplacementBoundary(
    MutatorRng& rng, InstructionDisplacementInfo& info, int64_t index_offset,
    size_t num_boundaries) {
  if (info.valid()) {
    int64_t shifted = (int64_t)info.instruction_boundary + index_offset;
    // If the shifted value is out of bounds, randomize it.
    if (shifted < 0 || shifted >= num_boundaries) {
      shifted = RandomIndex(rng, num_boundaries);
    }
    info.instruction_boundary = (size_t)shifted;
  }
}

}  // namespace

// This function tries to determine which instruction each displacement of a
// newly mutated instruction should point to.
// 1) If the old instruction has the same kind of displacement (they are both
// direct branches, for example) and the byte displacement has not changed (the
// mutator did not touch the encoded displacement value) then copy the
// instruction index from the old instruction to the new instruction.
// 2) If the byte displacement was touched by the mutator, then randomize the
// instruction index. The encoded byte displacement may be out of sync with the
// symbolic instruction index, so we can't reason how the mutation affected the
// index - just assume that any mutation randomizes the index. Even if the
// encoding was kept in sync with the index, a mutation could result in a byte
// displacement that didn't point to a valid instruction boundary and we'd need
// to figure out how to fix this up in an unbiased way. In general, it's simpler
// to completely randomize the displacement when it is touched.
// 3) If the new instruction has a displacement but the old instruction does
// not, then randomize the displacement. Newly discovered displacements should
// be both random and valid.
template <typename Arch>
void CopyOrRandomizeInstructionDisplacementBoundaries(
    MutatorRng& rng, const Instruction<Arch>& original,
    Instruction<Arch>& mutated, size_t num_boundaries) {
  CopyOrRandomizeInstructionDisplacementBoundary(
      rng, original.direct_branch, mutated.direct_branch, num_boundaries);
}

template void CopyOrRandomizeInstructionDisplacementBoundaries(
    MutatorRng& rng, const Instruction<X86_64>& original,
    Instruction<X86_64>& mutated, size_t num_boundaries);
template void CopyOrRandomizeInstructionDisplacementBoundaries(
    MutatorRng& rng, const Instruction<AArch64>& original,
    Instruction<AArch64>& mutated, size_t num_boundaries);

// template <typename Arch>
// void GenerateFLDCWBiasedBytes(MutatorRng& rng,
//                               InstructionByteBuffer<Arch>& bytes) {
//   static_assert(std::is_same_v<Arch, X86_64>,
//                 "FLDCW bias only implemented for X86_64");

//   // FLDCW指令的操作码：0xD9 /5 (ModR/M字节中reg=101)
//   // 可能的FLDCW指令模式：
//   const std::vector<std::vector<uint8_t>> fldcw_patterns = {
//       // 1. 寄存器间接寻址 (mod=00, reg=101, rm=xxx)
//       {0xD9, 0x28},  // fldcw [rax] (ModRM=0x28: 00 101 000)
//       {0xD9, 0x29},  // fldcw [rcx] (0x29: 00 101 001)
//       {0xD9, 0x2A},  // fldcw [rdx] (0x2A: 00 101 010)
//       {0xD9, 0x2B},  // fldcw [rbx] (0x2B: 00 101 011)
//       {0xD9, 0x2E},  // fldcw [rsi] (0x2E: 00 101 110)
//       {0xD9, 0x2F},  // fldcw [rdi] (0x2F: 00 101 111)

//       // 2. 带8位位移 (mod=01, reg=101, rm=xxx)
//       {0xD9, 0x68, 0x10},  // fldcw [rax+0x10] (0x68: 01 101 000)
//       {0xD9, 0x69, 0x20},  // fldcw [rcx+0x20] (0x69: 01 101 001)
//       {0xD9, 0x6E, 0x08},  // fldcw [rsi+0x08] (0x6E: 01 101 110)
//       {0xD9, 0x6F, 0x0C},  // fldcw [rdi+0x0C] (0x6F: 01 101 111)

//       // 3. 带32位位移 (mod=10, reg=101, rm=xxx)
//       {0xD9, 0xA8, 0x00, 0x10, 0x00,
//        0x00},  // fldcw [rax+0x1000] (0xA8: 10 101 000)
//       {0xD9, 0xA9, 0x00, 0x20, 0x00,
//        0x00},  // fldcw [rcx+0x2000] (0xA9: 10 101 001)
//       {0xD9, 0xAE, 0x00, 0x30, 0x00,
//        0x00},  // fldcw [rsi+0x3000] (0xAE: 10 101 110)

//       // 4. SIB 复杂寻址
//       {0xD9, 0x2C, 0x24},  // fldcw [rsp] (ModRM=0x2C: 00 101 100 + SIB=0x24)
//       {0xD9, 0x6D, 0x00},  // fldcw [rbp+0] (0x6D: 01 101 101)

//       // 5. 64-bit 扩展寄存器（使用 REX 前缀）
//       {0x41, 0xD9, 0x28},       // fldcw [r8] (REX.B=1, ModRM=0x28)
//       {0x41, 0xD9, 0x29},       // fldcw [r9] (REX.B=1, ModRM=0x29)
//       {0x41, 0xD9, 0x6A, 0x10}  // fldcw [r10+0x10] (REX.B=1, 0x6A: 01 101
//       010)
//   };

//   // 随机选择一个FLDCW模式
//   size_t pattern_idx = RandomIndex(rng, fldcw_patterns.size());
//   const auto& pattern = fldcw_patterns[pattern_idx];

//   // 复制模式到字节缓冲区
//   size_t copy_size = std::min(pattern.size(), sizeof(bytes));
//   for (size_t i = 0; i < copy_size; ++i) {
//     bytes[i] = pattern[i];
//   }

//   // 随机化剩余字节（如果需要）
//   for (size_t i = copy_size; i < sizeof(bytes); ++i) {
//     bytes[i] = static_cast<uint8_t>(rng());
//   }
// }

template <typename Arch>
void ShiftOrRandomizeInstructionDisplacementBoundaries(
    MutatorRng& rng, Instruction<Arch>& instruction, int64_t index_offset,
    size_t num_boundaries) {
  ShiftOrRandomizeInstructionDisplacementBoundary(
      rng, instruction.direct_branch, index_offset, num_boundaries);
}

template void ShiftOrRandomizeInstructionDisplacementBoundaries(
    MutatorRng& rng, Instruction<X86_64>& instruction, int64_t index_offset,
    size_t num_boundaries);
template void ShiftOrRandomizeInstructionDisplacementBoundaries(
    MutatorRng& rng, Instruction<AArch64>& instruction, int64_t index_offset,
    size_t num_boundaries);

template <typename Arch>
bool MutateSingleInstruction(MutatorRng& rng, const Instruction<Arch>& original,
                             Instruction<Arch>& mutated) {
  InstructionByteBuffer<Arch> bytes;
  size_t num_old_bytes = original.encoded.size();

  // Individual mutations may not be successful. In some parts of the encoding
  // space it may be more difficult to mutate than others. Retry the mutation a
  // finite number of times so that callers of this function can assume that it
  // almost always succeeds.
  // In theory this could be an infinite loop, but it's implemented as a finite
  // loop to limit the worst case behavior.
  for (size_t i = 0; i < 64; ++i) {
    if constexpr (kInstructionInfo<Arch>.max_size !=
                  kInstructionInfo<Arch>.min_size) {
      // Randomize the buffer - a mutation could cause the instruction to become
      // larger so we need to randomize the bytes after the instruction.
      // It's simpler/faster to randomize the whole buffer since we generate
      // random bytes in parallel.
      RandomizeBuffer(rng, bytes);
    }

    // Copy in the original bytes.
    memcpy(bytes, original.encoded.data(), num_old_bytes);

    // Keep trying to mutate until we hit a valid instruction.
    // This lets us "push through" sparse parts of the encoding space.
    // We don't want to mutate too much, however, because at some point it
    // stops being a mutation and starts being a new random instruction.
    // This implementation is a bit ad-hoc and could use some experimentation
    // and tunning for the constants, etc.
    for (size_t j = 0; j < 3; ++j) {
      // TODO(ncbray): other mutation modes. Randomize byte, swap bytes, etc.
      FlipRandomBit(rng, bytes, num_old_bytes);
      if (InstructionFromBytes(bytes, sizeof(bytes), mutated)) {
        return true;
      }
    }
  }
  return false;
}

template bool MutateSingleInstruction(MutatorRng& rng,
                                      const Instruction<X86_64>& original,
                                      Instruction<X86_64>& mutated);
template bool MutateSingleInstruction(MutatorRng& rng,
                                      const Instruction<AArch64>& original,
                                      Instruction<AArch64>& mutated);

// template <typename Arch>
// bool GenerateSingleInstruction(MutatorRng& rng,
//                                Instruction<Arch>& instruction) {
//   InstructionByteBuffer<Arch> bytes;
//   // It may take us a few tries to find a random set of bytes that decompile.
//   // In theory this could be an infinite loop, but it's implemented as a
//   finite
//   // loop to limit the worst case behavior.
//   for (size_t i = 0; i < 64; ++i) {
//     RandomizeBuffer(rng, bytes);
//     if (InstructionFromBytes(bytes, sizeof(bytes), instruction)) return true;
//   }
//   return false;
// }

// 新的、经过增强的 GenerateSingleInstruction 实现
template <typename Arch>
bool GenerateSingleInstruction(MutatorRng& rng,
                               Instruction<Arch>& instruction) {
  // 仅对 X86_64 架构应用此特殊逻辑
  if constexpr (std::is_same_v<Arch, X86_64>) {
    // 设定一个概率（例如 30%）来生成我们的目标指令
    if (RandomIndex(rng, 100) < 90) {
      // 定义我们想要生成的指令的二进制模式列表。
      // 这些列表是从你之前的 InsertFLDCWInstruction 和 InsertIDIVInstruction
      // 实现中复制过来的，
      // 以保证指令的多样性。
      static const std::vector<std::vector<uint8_t>> fldcw_patterns = {
          {0xD9, 0x28},
          {0xD9, 0x29},
          {0xD9, 0x2A},
          {0xD9, 0x2B},
          {0xD9, 0x2E},
          {0xD9, 0x2F},
          {0xD9, 0x68, 0x10},
          {0xD9, 0x69, 0x20},
          {0xD9, 0x6E, 0x08},
          {0xD9, 0x6F, 0x0C},
          {0xD9, 0xA8, 0x00, 0x10, 0x00, 0x00},
          {0xD9, 0xA9, 0x00, 0x20, 0x00, 0x00},
          {0xD9, 0xAE, 0x00, 0x30, 0x00, 0x00},
          {0xD9, 0x2C, 0x24},
          {0xD9, 0x6D, 0x00},
          {0x41, 0xD9, 0x28},
          {0x41, 0xD9, 0x29},
          {0x41, 0xD9, 0x6A, 0x10}};

      static const std::vector<std::vector<uint8_t>> idiv_patterns = {
          {0xF6, 0xF8},       {0xF6, 0xF9},       {0xF6, 0xFA},
          {0xF6, 0xFB},       {0xF6, 0xFC},       {0xF6, 0xFD},
          {0xF6, 0xFE},       {0xF6, 0xFF},       {0x48, 0xF7, 0xF8},
          {0x48, 0xF7, 0xF9}, {0x48, 0xF7, 0xFA}, {0x48, 0xF7, 0xFB},
          {0x48, 0xF7, 0xFC}, {0x48, 0xF7, 0xFD}, {0x48, 0xF7, 0xFE},
          {0x48, 0xF7, 0xFF}, {0x48, 0xF7, 0x38}, {0x48, 0xF7, 0x39},
          {0x48, 0xF7, 0x7E}};

      // 随机决定是生成 FLDCW 还是 IDIV (50/50 概率)
      if (RandomIndex(rng, 2) == 0) {
        // 生成 FLDCW
        size_t pattern_idx = RandomIndex(rng, fldcw_patterns.size());
        const auto& pattern = fldcw_patterns[pattern_idx];
        if (InstructionFromBytes(pattern.data(), pattern.size(), instruction)) {
          return true;  // 成功生成并解析了指令
        }
      } else {
        // 生成 IDIV
        size_t pattern_idx = RandomIndex(rng, idiv_patterns.size());
        const auto& pattern = idiv_patterns[pattern_idx];
        if (InstructionFromBytes(pattern.data(), pattern.size(), instruction)) {
          return true;  // 成功生成并解析了指令
        }
      }
      // 如果从预设模式生成失败（虽然不太可能），我们会自动回退到下面的纯随机生成逻辑。
    }
  }

  InstructionByteBuffer<Arch> bytes;
  for (size_t i = 0; i < 64; ++i) {
    RandomizeBuffer(rng, bytes);  // 直接传数组
    if (InstructionFromBytes(bytes, sizeof(bytes), instruction)) {
      return true;
    }
  }
  // 如果所有尝试都失败了，则返回 false
  return false;
}
// template <typename Arch>
// bool GenerateSingleInstruction(MutatorRng& rng,
//                                Instruction<Arch>& instruction) {
//   InstructionByteBuffer<Arch> bytes;

//   // 设置偏向FLDCW指令的概率（30%的概率生成FLDCW指令）
//   constexpr double FLDCW_BIAS_PROBABILITY = 0.8;
//   std::uniform_real_distribution<double> prob_dist(0.0, 1.0);

//   for (size_t i = 0; i < 64; ++i) {
//     if constexpr (std::is_same_v<Arch, X86_64>) {
//       // 对于x86_64架构，有概率偏向生成FLDCW指令
//       if (prob_dist(rng) < FLDCW_BIAS_PROBABILITY) {
//         // 生成偏向FLDCW指令的字节序列
//         // GenerateFLDCWBiasedBytes(rng, bytes);
//         GenerateFLDCWBiasedBytes<Arch>(rng, bytes);
//       } else {
//         // 正常随机生成
//         RandomizeBuffer(rng, bytes);
//       }
//     } else {
//       // 其他架构保持原有逻辑
//       RandomizeBuffer(rng, bytes);
//     }

//     if (InstructionFromBytes(bytes, sizeof(bytes), instruction)) return true;
//   }
//   return false;
// }

// 在现有的函数声明后添加
template bool GenerateSingleInstruction(MutatorRng& rng,
                                        Instruction<X86_64>& instruction);
template bool GenerateSingleInstruction(MutatorRng& rng,
                                        Instruction<AArch64>& instruction);

void FlipBit(uint8_t* buffer, size_t bit) {
  buffer[bit >> 3] ^= 1 << (bit & 0b111);
}

void FlipRandomBit(MutatorRng& rng, uint8_t* buffer, size_t buffer_size) {
  FlipBit(buffer, RandomIndex(rng, buffer_size * 8));
}

// Throw away instruction until we're under the length limit.
template <typename Arch>
bool LimitProgramLength(MutatorRng& rng, Program<Arch>& program,
                        size_t max_len) {
  bool modified = false;
  DeleteInstruction<Arch> m;
  while (program.ByteLen() > max_len) {
    CHECK_GT(program.NumInstructions(), 0);
    m.Mutate(rng, program, program);
    modified = true;
  }
  return modified;
}

template bool LimitProgramLength(MutatorRng& rng, Program<X86_64>& program,
                                 size_t max_len);
template bool LimitProgramLength(MutatorRng& rng, Program<AArch64>& program,
                                 size_t max_len);

}  // namespace silifuzz
