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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_PROGRAM_MUTATION_OPS_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_PROGRAM_MUTATION_OPS_H_

#include <cstddef>
#include <cstdint>
#include <vector>

#include "./fuzzer/program.h"
#include "./fuzzer/program_mutator.h"

namespace silifuzz {

// Try to generate a random instruction from scratch.
// Returns `true` is successful.

template <typename Arch>
bool GenerateSingleInstruction(MutatorRng& rng, Instruction<Arch>& instruction);

// Mutate `original` and place the output in `mutated` using the default
// single-instruction mutation policy.
// Returns `true` is successful.
template <typename Arch>
bool MutateSingleInstruction(MutatorRng& rng, const Instruction<Arch>& original,
                             Instruction<Arch>& mutated);

// Assuming `original` is the original instruction and `mutated` is a modified
// copy, copy the instruction displacement boundaries if the encoded
// displacement is present in both `original` and `mutated` and did not change.
// Otherwise, randomize the boundaries that are present in `mutated` but not
// `original`, or were modified between the two versions.
template <typename Arch>
void CopyOrRandomizeInstructionDisplacementBoundaries(
    MutatorRng& rng, const Instruction<Arch>& original,
    Instruction<Arch>& mutated, size_t num_boundaries);

// Shift the instruction displacement boundaries of `instruction` so that the
// relative displacements are same after the instruction's index has shifted to
// index + `index_offset`. This is done by also shifting the displacements by
// `index_offset`.
// If keeping the new displacement no longer points to a valid instruction
// boundary, randomize the displacement to point to a valid boundary.
// This function is used when we want to copy one or more instructions from
// somewhere and we want to ensure the displacements of the copied instructions
// have the same relative shape when placed at their new location rather than
// preserving the absolute values.
template <typename Arch>
void ShiftOrRandomizeInstructionDisplacementBoundaries(
    MutatorRng& rng, Instruction<Arch>& instruction, int64_t index_offset,
    size_t num_boundaries);

template <typename Arch>
void ShiftOrRandomizeInstructionDisplacementBoundaries(
    MutatorRng& rng, std::vector<Instruction<Arch>>& block,
    int64_t index_offset, size_t num_boundaries) {
  for (Instruction<Arch>& instruction : block) {
    ShiftOrRandomizeInstructionDisplacementBoundaries(
        rng, instruction, index_offset, num_boundaries);
  }
}

// Insert a randomly generated instruction at a random boundary in the program.
template <typename Arch>
class InsertGeneratedInstruction : public ProgramMutator<Arch> {
 public:
  InsertGeneratedInstruction() {}

  // Returns `true` if successful, returns `false` if the the random number
  // generator was deeply unlucky.
  bool Mutate(MutatorRng& rng, Program<Arch>& program,
              const Program<Arch>& other) override {
    Instruction<Arch> insn;
    bool success = GenerateSingleInstruction(rng, insn);
    if (!success) return false;

    // Inserting the instruction will increase the number of potential
    // instruction boundaries by one.
    RandomizeInstructionDisplacementBoundaries(
        rng, insn, program.NumInstructionBoundaries() + 1);

    size_t insert_boundary = program.RandomInstructionBoundary(rng);
    bool steal_displacements = RandomIndex(rng, 2);
    program.InsertInstruction(insert_boundary, steal_displacements, insn);
    return true;
  }
};

// Randomly modify a random instruction in the program.
template <typename Arch>
class MutateInstruction : public ProgramMutator<Arch> {
 public:
  MutateInstruction() {}

  // Returns `true` if successful, returns `false` if the the random number
  // generator was unlucky, although some instructions may be more difficult to
  // successfully mutate than others.
  bool Mutate(MutatorRng& rng, Program<Arch>& program,
              const Program<Arch>& other) override {
    // Is there anything to mutate?
    if (program.NumInstructions() == 0) return false;

    // Select a random instruction.
    size_t target = program.RandomInstructionIndex(rng);
    const Instruction<Arch>& original = program.GetInstruction(target);

    // Try to mutate.
    Instruction<Arch> mutated{};
    if (MutateSingleInstruction(rng, original, mutated)) {
      CopyOrRandomizeInstructionDisplacementBoundaries(
          rng, original, mutated, program.NumInstructionBoundaries());
      program.SetInstruction(target, mutated);
      return true;
    }
    return false;
  }
};

// Remove a random instruction from the program.
template <typename Arch>
class DeleteInstruction : public ProgramMutator<Arch> {
 public:
  explicit DeleteInstruction(size_t minimum_instructions = 0)
      : minimum_instructions_(minimum_instructions) {}

  // Returns `true` if successful, returns `false` if the program is too small
  // and we should not delete any instructions.
  bool Mutate(MutatorRng& rng, Program<Arch>& program,
              const Program<Arch>& other) override {
    // Can an instruction be removed without going below the minimum?
    if (program.NumInstructions() <= minimum_instructions_) return false;

    // Remove a random instruction.
    size_t victim = program.RandomInstructionIndex(rng);
    program.RemoveInstruction(victim);
    return true;
  }

 private:
  size_t minimum_instructions_;
};

template <typename Arch>
class SwapInstructions : public ProgramMutator<Arch> {
 public:
  SwapInstructions() {}

  bool Mutate(MutatorRng& rng, Program<Arch>& program,
              const Program<Arch>& other) override {
    // Need at least two instructions to swap.
    if (program.NumInstructions() < 2) return false;

    // Select the targets.
    size_t a = program.RandomInstructionIndex(rng);
    size_t b = program.RandomInstructionIndex(rng);
    while (a == b) {
      b = program.RandomInstructionIndex(rng);
    }

    // Copy the instructions.
    Instruction<Arch> a_instruction = program.GetInstruction(a);
    Instruction<Arch> b_instruction = program.GetInstruction(b);

    // Swap the instructions.
    // Note that the branch displacements are not affected by this operation.
    // A branch that is swapped will target the same absolute location.
    // An alternative mutation would be to move the displacement how ever much
    // the instruction moved and re-randomize it if it goes out of range.
    program.SetInstruction(a, b_instruction);
    program.SetInstruction(b, a_instruction);

    return true;
  }
};

// Copy a random chunk from the other program and insert it at a random
// instruction boundary.
template <typename Arch>
class CrossoverInsert : public ProgramMutator<Arch> {
 public:
  CrossoverInsert() {}

  bool Mutate(MutatorRng& rng, Program<Arch>& program,
              const Program<Arch>& other) override {
    // Is there anything to crossover with?
    if (other.NumInstructions() == 0) return false;

    // Determine how much of the other program we want to copy.
    // src_size = [1, NumInstructions()]
    size_t max_size = other.NumInstructions();
    size_t src_size = RandomIndex(rng, max_size) + 1;
    size_t src_index = RandomIndex(rng, other.NumInstructions() - src_size + 1);

    // We must copy because `program` and `other` can be aliased.
    std::vector<Instruction<Arch>> block =
        other.CopyInstructionBlock(src_index, src_size);

    // Determine where we want to insert the block.
    size_t dst_boundary = program.RandomInstructionBoundary(rng);

    // Fixup the branch displacements of the copied instructions.
    int64_t index_offset = (int64_t)dst_boundary - (int64_t)src_index;
    ShiftOrRandomizeInstructionDisplacementBoundaries(
        rng, block, index_offset,
        program.NumInstructionBoundaries() + block.size());

    // Insert.
    bool steal_displacements = RandomIndex(rng, 2);
    program.InsertInstructionBlock(dst_boundary, steal_displacements, block);
    return true;
  }
};

// Copy a random chunk from the other program and overwrite the current program
// at a random instruction idnex.
template <typename Arch>
class CrossoverOverwrite : public ProgramMutator<Arch> {
 public:
  CrossoverOverwrite() {}

  bool Mutate(MutatorRng& rng, Program<Arch>& program,
              const Program<Arch>& other) override {
    // Is there anything to overwrite?
    if (program.NumInstructions() == 0) return false;

    // Is there anything to crossover with?
    if (other.NumInstructions() == 0) return false;

    // Determine how much of the other program we want to copy.
    // We do not want to overwrite more than half the current program and cannot
    // copy more from the other program than exists.
    size_t max_size = std::min(std::max(1UL, program.NumInstructions() / 2),
                               other.NumInstructions());
    size_t src_size = RandomIndex(rng, max_size) + 1;
    size_t src_index = RandomIndex(rng, other.NumInstructions() - src_size + 1);

    // We must copy because `program` and `other` can be aliased.
    std::vector<Instruction<Arch>> block =
        other.CopyInstructionBlock(src_index, src_size);

    // Determine where we want to insert the block.
    size_t dst_index =
        RandomIndex(rng, program.NumInstructions() - block.size() + 1);

    // Fixup the branch displacements of the copied instructions.
    int64_t index_offset = (int64_t)dst_index - (int64_t)src_index;
    ShiftOrRandomizeInstructionDisplacementBoundaries(
        rng, block, index_offset, program.NumInstructionBoundaries());

    // Overwrite.
    program.SetInstructionBlock(dst_index, block);
    return true;
  }
};

// // 添加 LDMXCSR 指令生成器（修正 patterns）
// template <typename Arch>
// class InsertLDMXCSRInstruction : public ProgramMutator<Arch> {
//  public:
//   InsertLDMXCSRInstruction() {}

//   bool Mutate(MutatorRng& rng, Program<Arch>& program,
//               const Program<Arch>& other) override {
//     if constexpr (std::is_same_v<Arch, X86_64>) {
//       Instruction<X86_64> insn;

//       // 修正后的有效 LDMXCSR patterns (0F AE /2, reg=010)
//       // 包括寄存器间接、带位移、SIB，兼容 x86_64（部分添加 REX）
//       const std::vector<std::vector<uint8_t>> ldmxcsr_patterns = {
//         // 1. 寄存器间接寻址 (mod=00, reg=010, rm=xxx)
//         {0x0F, 0xAE, 0x10},  // ldmxcsr [rax/eax] (ModRM=0x10: 00 010 000)
//         {0x0F, 0xAE, 0x11},  // ldmxcsr [rcx/ecx] (0x11: 00 010 001)
//         {0x0F, 0xAE, 0x12},  // ldmxcsr [rdx/edx] (0x12: 00 010 010)
//         {0x0F, 0xAE, 0x13},  // ldmxcsr [rbx/ebx] (0x13: 00 010 011)
//         {0x0F, 0xAE, 0x16},  // ldmxcsr [rsi/esi] (0x16: 00 010 110)
//         {0x0F, 0xAE, 0x17},  // ldmxcsr [rdi/edi] (0x17: 00 010 111)

//         // 2. 带8位位移 (mod=01, reg=010, rm=xxx)
//         {0x0F, 0xAE, 0x50, 0x10},  // ldmxcsr [rax+0x10] (0x50: 01 010 000)
//         {0x0F, 0xAE, 0x51, 0x20},  // ldmxcsr [rcx+0x20] (0x51: 01 010 001)
//         {0x0F, 0xAE, 0x56, 0x08},  // ldmxcsr [rsi+0x08] (0x56: 01 010 110)
//         {0x0F, 0xAE, 0x57, 0x0C},  // ldmxcsr [rdi+0x0C] (0x57: 01 010 111)

//         // 3. 带32位位移 (mod=10, reg=010, rm=xxx)
//         {0x0F, 0xAE, 0x90, 0x00, 0x10, 0x00, 0x00},  // ldmxcsr [rax+0x1000]
//         (0x90: 10 010 000) {0x0F, 0xAE, 0x91, 0x00, 0x20, 0x00, 0x00},  //
//         ldmxcsr [rcx+0x2000] (0x91: 10 010 001) {0x0F, 0xAE, 0x96, 0x00,
//         0x30, 0x00, 0x00},  // ldmxcsr [rsi+0x3000] (0x96: 10 010 110)

//         // 4. SIB 复杂寻址（栈相关）
//         {0x0F, 0xAE, 0x14, 0x24},  // ldmxcsr [esp] (ModRM=0x14: 00 010 100 +
//         SIB=0x24: no index, base=esp) {0x0F, 0xAE, 0x55, 0x00},  // ldmxcsr
//         [rbp+0] (0x55: 01 010 101, ebp as stack base) {0x0F, 0xAE, 0x96,
//         0x00, 0x00, 0x00, 0x00},  // ldmxcsr [rsi+0] (32-bit disp=0)

//         // 5. 添加 REX 前缀的 64-bit 变体（扩展寄存器）
//         {0x41, 0x0F, 0xAE, 0x10},  // ldmxcsr [r8] (REX.B=1, ModRM=0x10)
//         {0x41, 0x0F, 0xAE, 0x11}   // ldmxcsr [r9] (REX.B=1, ModRM=0x11)
//       };

//       size_t pattern_idx = RandomIndex(rng, ldmxcsr_patterns.size());
//       const auto& pattern = ldmxcsr_patterns[pattern_idx];

//       insn.encoded.Copy(pattern.data(), pattern.size());

//       // 设置位移边界（LDMXCSR 非分支，但保留以兼容）
//       RandomizeInstructionDisplacementBoundaries(
//           rng, insn, program.NumInstructionBoundaries() + 1);

//       size_t insert_boundary = program.RandomInstructionBoundary(rng);
//       bool steal_displacements = RandomIndex(rng, 2);
//       program.InsertInstruction(insert_boundary, steal_displacements, insn);
//       return true;
//     }
//     return false;
//   }
// };

// 添加 IDIV 指令生成器（原有正确，添加更多内存变体以增加多样性）
template <typename Arch>
class InsertIDIVInstruction : public ProgramMutator<Arch> {
 public:
  InsertIDIVInstruction() {}

  bool Mutate(MutatorRng& rng, Program<Arch>& program,
              const Program<Arch>& other) override {
    if constexpr (std::is_same_v<Arch, X86_64>) {
      Instruction<X86_64> insn;

      // IDIV patterns（原有 + 新增内存操作数变体）
      const std::vector<std::vector<uint8_t>> idiv_patterns = {
          // 8位 IDIV (寄存器)
          {0xF6, 0xF8},  // idiv al (ModRM=0xF8: 11 111 000)
          {0xF6, 0xF9},  // idiv cl
          {0xF6, 0xFA},  // idiv dl
          {0xF6, 0xFB},  // idiv bl
          {0xF6, 0xFC},  // idiv ah
          {0xF6, 0xFD},  // idiv ch
          {0xF6, 0xFE},  // idiv dh
          {0xF6, 0xFF},  // idiv bh

          // 64位 IDIV (REX.W + 寄存器)
          {0x48, 0xF7, 0xF8},  // idiv rax
          {0x48, 0xF7, 0xF9},  // idiv rcx
          {0x48, 0xF7, 0xFA},  // idiv rdx
          {0x48, 0xF7, 0xFB},  // idiv rbx
          {0x48, 0xF7, 0xFC},  // idiv rsp
          {0x48, 0xF7, 0xFD},  // idiv rbp
          {0x48, 0xF7, 0xFE},  // idiv rsi
          {0x48, 0xF7, 0xFF},  // idiv rdi

          // 新增：64位 IDIV 内存操作数 (例如 idiv qword ptr [reg])
          {0x48, 0xF7, 0x38},  // idiv qword ptr [rax] (ModRM=0x38: 00 111 000)
          {0x48, 0xF7, 0x39},  // idiv qword ptr [rcx] (0x39: 00 111 001)
          {0x48, 0xF7, 0x7E},  // idiv qword ptr [rsi] (0x7E: 00 111 110)

          // 带REX前缀的64位IDIV
          {0x48, 0xF7, 0xF8},  // idiv rax
          {0x48, 0xF7, 0xF9},  // idiv rcx
          {0x48, 0xF7, 0xFA},  // idiv rdx
          {0x48, 0xF7, 0xFB},  // idiv rbx
          {0x48, 0xF7, 0xFC},  // idiv rsp
          {0x48, 0xF7, 0xFD},  // idiv rbp
          {0x48, 0xF7, 0xFE},  // idiv rsi
          {0x48, 0xF7, 0xFF},  // idiv rdi

          // 内存操作数的IDIV
          {0xF7, 0x38},  // idiv dword ptr [rax]
          {0xF7, 0x39},  // idiv dword ptr [rcx]
          {0xF7, 0x3A},  // idiv dword ptr [rdx]
          {0xF7, 0x3B},  // idiv dword ptr [rbx]
          {0xF7, 0x3E},  // idiv dword ptr [rsi]
          {0xF7, 0x3F},  // idiv dword ptr [rdi]

          // 带位移的IDIV
          {0xF7, 0x78, 0x10},  // idiv dword ptr [rax+0x10]
          {0xF7, 0x79, 0x20},  // idiv dword ptr [rcx+0x20]
          {0xF7, 0x7A, 0x30},  // idiv dword ptr [rdx+0x30]

          // 64位内存操作数
          {0x48, 0xF7, 0x3A}  // idiv qword ptr [rdx]

      };

      size_t pattern_idx = RandomIndex(rng, idiv_patterns.size());
      const auto& pattern = idiv_patterns[pattern_idx];

      insn.encoded.Copy(pattern.data(), pattern.size());

      // 设置位移边界（IDIV 非分支，但保留）
      RandomizeInstructionDisplacementBoundaries(
          rng, insn, program.NumInstructionBoundaries() + 1);

      size_t insert_boundary = program.RandomInstructionBoundary(rng);
      bool steal_displacements = RandomIndex(rng, 2);
      program.InsertInstruction(insert_boundary, steal_displacements, insn);
      return true;
    }
    return false;
  }
};

// 添加 FLDCW 指令生成器
template <typename Arch>
class InsertFLDCWInstruction : public ProgramMutator<Arch> {
 public:
  InsertFLDCWInstruction() {}

  bool Mutate(MutatorRng& rng, Program<Arch>& program,
              const Program<Arch>& other) override {
    if constexpr (std::is_same_v<Arch, X86_64>) {
      Instruction<X86_64> insn;

      // FLDCW m2byte - 多种寻址模式 (opcode D9 /5, reg=101)
      const std::vector<std::vector<uint8_t>> fldcw_patterns = {
          // 1. 寄存器间接寻址 (mod=00, reg=101, rm=xxx)
          {0xD9, 0x28},  // fldcw [rax] (ModRM=0x28: 00 101 000)
          {0xD9, 0x29},  // fldcw [rcx] (0x29: 00 101 001)
          {0xD9, 0x2A},  // fldcw [rdx] (0x2A: 00 101 010)
          {0xD9, 0x2B},  // fldcw [rbx] (0x2B: 00 101 011)
          {0xD9, 0x2E},  // fldcw [rsi] (0x2E: 00 101 110)
          {0xD9, 0x2F},  // fldcw [rdi] (0x2F: 00 101 111)

          // 2. 带8位位移 (mod=01, reg=101, rm=xxx)
          {0xD9, 0x68, 0x10},  // fldcw [rax+0x10] (0x68: 01 101 000)
          {0xD9, 0x69, 0x20},  // fldcw [rcx+0x20] (0x69: 01 101 001)
          {0xD9, 0x6E, 0x08},  // fldcw [rsi+0x08] (0x6E: 01 101 110)
          {0xD9, 0x6F, 0x0C},  // fldcw [rdi+0x0C] (0x6F: 01 101 111)

          // 3. 带32位位移 (mod=10, reg=101, rm=xxx)
          {0xD9, 0xA8, 0x00, 0x10, 0x00,
           0x00},  // fldcw [rax+0x1000] (0xA8: 10 101 000)
          {0xD9, 0xA9, 0x00, 0x20, 0x00,
           0x00},  // fldcw [rcx+0x2000] (0xA9: 10 101 001)
          {0xD9, 0xAE, 0x00, 0x30, 0x00,
           0x00},  // fldcw [rsi+0x3000] (0xAE: 10 101 110)

          // 4. SIB 复杂寻址
          {0xD9, 0x2C,
           0x24},  // fldcw [rsp] (ModRM=0x2C: 00 101 100 + SIB=0x24)
          {0xD9, 0x6D, 0x00},  // fldcw [rbp+0] (0x6D: 01 101 101)

          // 5. 64-bit 扩展寄存器（使用 REX 前缀）
          {0x41, 0xD9, 0x28},  // fldcw [r8] (REX.B=1, ModRM=0x28)
          {0x41, 0xD9, 0x29},  // fldcw [r9] (REX.B=1, ModRM=0x29)
          {0x41, 0xD9, 0x6A, 0x10}
          // fldcw [r10+0x10] (REX.B=1, 0x6A: 01 101 010)
      };

      size_t pattern_idx = RandomIndex(rng, fldcw_patterns.size());
      const auto& pattern = fldcw_patterns[pattern_idx];

      insn.encoded.Copy(pattern.data(), pattern.size());

      RandomizeInstructionDisplacementBoundaries(
          rng, insn, program.NumInstructionBoundaries() + 1);

      size_t insert_boundary = program.RandomInstructionBoundary(rng);
      bool steal_displacements = RandomIndex(rng, 2);
      program.InsertInstruction(insert_boundary, steal_displacements, insn);
      return true;
    }
    return false;
  }
};

// ... (原有代码不变，包括 InsertFLDCWInstruction 和 InsertIDIVInstruction)

// 添加 FLDCW 后接 IDIV 的指令生成器
// template <typename Arch>
// class InsertFLDCWThenIDIV : public ProgramMutator<Arch> {
//  public:
//   InsertFLDCWThenIDIV() {}

//   bool Mutate(MutatorRng& rng, Program<Arch>& program,
//               const Program<Arch>& other) override {
//     if constexpr (std::is_same_v<Arch, X86_64>) {
//       // FLDCW patterns（从 InsertFLDCWInstruction 复用

//       const std::vector<std::vector<uint8_t>> fldcw_patterns = {
//         // 1. 寄存器间接寻址 (mod=00, reg=101, rm=xxx)
//         {0xD9, 0x28},  // fldcw [rax] (ModRM=0x28: 00 101 000)
//         {0xD9, 0x29},  // fldcw [rcx] (0x29: 00 101 001)
//         {0xD9, 0x2A},  // fldcw [rdx] (0x2A: 00 101 010)
//         {0xD9, 0x2B},  // fldcw [rbx] (0x2B: 00 101 011)
//         {0xD9, 0x2E},  // fldcw [rsi] (0x2E: 00 101 110)
//         {0xD9, 0x2F},  // fldcw [rdi] (0x2F: 00 101 111)

//         // 2. 带8位位移 (mod=01, reg=101, rm=xxx)
//         {0xD9, 0x68, 0x10},  // fldcw [rax+0x10] (0x68: 01 101 000)
//         {0xD9, 0x69, 0x20},  // fldcw [rcx+0x20] (0x69: 01 101 001)
//         {0xD9, 0x6E, 0x08},  // fldcw [rsi+0x08] (0x6E: 01 101 110)
//         {0xD9, 0x6F, 0x0C},  // fldcw [rdi+0x0C] (0x6F: 01 101 111)

//         // 3. 带32位位移 (mod=10, reg=101, rm=xxx)
//         {0xD9, 0xA8, 0x00, 0x10, 0x00, 0x00},  // fldcw [rax+0x1000] (0xA8:
//         10 101 000) {0xD9, 0xA9, 0x00, 0x20, 0x00, 0x00},  // fldcw
//         [rcx+0x2000] (0xA9: 10 101 001) {0xD9, 0xAE, 0x00, 0x30, 0x00, 0x00},
//         // fldcw [rsi+0x3000] (0xAE: 10 101 110)

//         // 4. SIB 复杂寻址
//         {0xD9, 0x2C, 0x24},  // fldcw [rsp] (ModRM=0x2C: 00 101 100 +
//         SIB=0x24) {0xD9, 0x6D, 0x00},  // fldcw [rbp+0] (0x6D: 01 101 101)

//         // 5. 64-bit 扩展寄存器（使用 REX 前缀）
//         {0x41, 0xD9, 0x28},  // fldcw [r8] (REX.B=1, ModRM=0x28)
//         {0x41, 0xD9, 0x29},  // fldcw [r9] (REX.B=1, ModRM=0x29)
//         {0x41, 0xD9, 0x6A, 0x10}  // fldcw [r10+0x10] (REX.B=1, 0x6A: 01 101
//         010)
//       };
//       // IDIV patterns（从 InsertIDIVInstruction 复用）
//       const std::vector<std::vector<uint8_t>> idiv_patterns = {
//         // 8位 IDIV (寄存器)
//         {0xF6, 0xF8}, // idiv al (ModRM=0xF8: 11 111 000)
//         {0xF6, 0xF9}, // idiv cl
//         {0xF6, 0xFA}, // idiv dl
//         {0xF6, 0xFB}, // idiv bl
//         {0xF6, 0xFC}, // idiv ah
//         {0xF6, 0xFD}, // idiv ch
//         {0xF6, 0xFE}, // idiv dh
//         {0xF6, 0xFF}, // idiv bh

//         // 64位 IDIV (REX.W + 寄存器)
//         {0x48, 0xF7, 0xF8}, // idiv rax
//         {0x48, 0xF7, 0xF9}, // idiv rcx
//         {0x48, 0xF7, 0xFA}, // idiv rdx
//         {0x48, 0xF7, 0xFB}, // idiv rbx
//         {0x48, 0xF7, 0xFC}, // idiv rsp
//         {0x48, 0xF7, 0xFD}, // idiv rbp
//         {0x48, 0xF7, 0xFE}, // idiv rsi
//         {0x48, 0xF7, 0xFF}, // idiv rdi

//         // 64位 IDIV 内存操作数 (例如 idiv qword ptr [reg])
//         {0x48, 0xF7, 0x38},  // idiv qword ptr [rax] (ModRM=0x38: 00 111 000)
//         {0x48, 0xF7, 0x39},  // idiv qword ptr [rcx] (0x39: 00 111 001)
//         {0x48, 0xF7, 0x7E}   // idiv qword ptr [rsi] (0x7E: 00 111 110)
//       };

//       // 步骤 1：插入 FLDCW
//       Instruction<X86_64> fldcw_insn;
//       size_t fldcw_pattern_idx = RandomIndex(rng, fldcw_patterns.size());
//       const auto& fldcw_pattern = fldcw_patterns[fldcw_pattern_idx];
//       fldcw_insn.encoded.Copy(fldcw_pattern.data(), fldcw_pattern.size());
//       RandomizeInstructionDisplacementBoundaries(
//           rng, fldcw_insn, program.NumInstructionBoundaries() + 1);

//       // 随机选择 FLDCW 的插入位置
//       size_t fldcw_boundary = program.RandomInstructionBoundary(rng);
//       bool steal_displacements = RandomIndex(rng, 2);
//       program.InsertInstruction(fldcw_boundary, steal_displacements,
//       fldcw_insn);

//       // 步骤 2：在 FLDCW 之后插入 IDIV
//       Instruction<X86_64> idiv_insn;
//       size_t idiv_pattern_idx = RandomIndex(rng, idiv_patterns.size());
//       const auto& idiv_pattern = idiv_patterns[idiv_pattern_idx];
//       idiv_insn.encoded.Copy(idiv_pattern.data(), idiv_pattern.size());
//       RandomizeInstructionDisplacementBoundaries(
//           rng, idiv_insn, program.NumInstructionBoundaries() + 1);

//       // 确保 IDIV 在 FLDCW 之后（可能有间隔）
//       // 计算 FLDCW 插入后的新指令索引
//       size_t fldcw_index = fldcw_boundary; // FLDCW 的指令索引
//       size_t program_size = program.NumInstructions(); // 当前程序指令数
//       if (program_size <= fldcw_index + 1) {
//         // 如果程序太短，直接在 FLDCW 后插入 IDIV
//         program.InsertInstruction(fldcw_index + 1, steal_displacements,
//         idiv_insn);
//       } else {
//         // 在 FLDCW 之后随机选择一个插入点（允许间隔）
//         size_t idiv_index = fldcw_index + 1 + RandomIndex(rng, program_size -
//         fldcw_index); program.InsertInstruction(idiv_index,
//         steal_displacements, idiv_insn);
//       }

//       return true;
//     }
//     return false;
//   }
// };
template <typename Arch>
class InsertFLDCWThenIDIV : public ProgramMutator<Arch> {
 public:
  InsertFLDCWThenIDIV() {}

  bool Mutate(MutatorRng& rng, Program<Arch>& program,
              const Program<Arch>& other) override {
    if constexpr (std::is_same_v<Arch, X86_64>) {
      // FLDCW patterns
      const std::vector<std::vector<uint8_t>> fldcw_patterns = {
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

      // IDIV patterns
      const std::vector<std::vector<uint8_t>> idiv_patterns = {
          {0xF6, 0xF8},       {0xF6, 0xF9},       {0xF6, 0xFA},
          {0xF6, 0xFB},       {0xF6, 0xFC},       {0xF6, 0xFD},
          {0xF6, 0xFE},       {0xF6, 0xFF},       {0x48, 0xF7, 0xF8},
          {0x48, 0xF7, 0xF9}, {0x48, 0xF7, 0xFA}, {0x48, 0xF7, 0xFB},
          {0x48, 0xF7, 0xFC}, {0x48, 0xF7, 0xFD}, {0x48, 0xF7, 0xFE},
          {0x48, 0xF7, 0xFF}, {0x48, 0xF7, 0x38}, {0x48, 0xF7, 0x39},
          {0x48, 0xF7, 0x7E}};

      // 1. 创建并插入 FLDCW 指令
      Instruction<X86_64> fldcw_insn;
      size_t fldcw_pattern_idx = RandomIndex(rng, fldcw_patterns.size());
      const auto& fldcw_pattern = fldcw_patterns[fldcw_pattern_idx];
      fldcw_insn.encoded.Copy(fldcw_pattern.data(), fldcw_pattern.size());

      // 设置位移边界
      RandomizeInstructionDisplacementBoundaries(
          rng, fldcw_insn, program.NumInstructionBoundaries() + 1);

      // 选择插入位置
      size_t fldcw_boundary = program.RandomInstructionBoundary(rng);
      bool steal_displacements = RandomIndex(rng, 2);
      program.InsertInstruction(fldcw_boundary, steal_displacements,
                                fldcw_insn);

      // 2. 创建 IDIV 指令
      Instruction<X86_64> idiv_insn;
      size_t idiv_pattern_idx = RandomIndex(rng, idiv_patterns.size());
      const auto& idiv_pattern = idiv_patterns[idiv_pattern_idx];
      idiv_insn.encoded.Copy(idiv_pattern.data(), idiv_pattern.size());

      // 设置位移边界
      RandomizeInstructionDisplacementBoundaries(
          rng, idiv_insn, program.NumInstructionBoundaries() + 1);

      // 计算 IDIV 的插入位置 - 间隔2～6条指令
      size_t num_instructions = program.NumInstructions();
      if (num_instructions == 0) {
        // 如果程序为空（不太可能，因为我们刚插入了一个指令）
        program.InsertInstruction(0, steal_displacements, idiv_insn);
      } else {
        // 控制间隔指令数量为2～6条
        size_t min_gap = 2;  // 最小间隔2条指令
        size_t max_gap = 8;  // 最大间隔6条指令
        size_t gap = min_gap +
                     RandomIndex(rng, max_gap - min_gap + 1);  // 2到6条间隔指令

        // 计算IDIV插入边界
        size_t idiv_boundary = fldcw_boundary + gap;

        // 确保不超出程序边界
        size_t max_boundary = program.NumInstructionBoundaries() - 1;
        if (idiv_boundary > max_boundary) {
          idiv_boundary = max_boundary;
        }

        program.InsertInstruction(idiv_boundary, steal_displacements,
                                  idiv_insn);
      }

      return true;
    }
    return false;
  }
};

// Remove instructions until `program.NumBytes()` <= `max_len`.
// Returns `true` if the program was modified.
template <typename Arch>
bool LimitProgramLength(MutatorRng& rng, Program<Arch>& program,
                        size_t max_len);

// Exported for testing
void FlipBit(uint8_t* buffer, size_t bit);
void FlipRandomBit(MutatorRng& rng, uint8_t* buffer, size_t buffer_size);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_PROGRAM_MUTATION_OPS_H_
