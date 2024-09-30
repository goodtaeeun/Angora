#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include "./abilist.h"
#include "./debug.h"
#include "./defs.h"
#include "./util.h"
#include "./version.h"

using namespace llvm;
// only do taint tracking, used for compile 3rd libraries.
static cl::opt<bool> DFSanMode("DFSanMode", cl::desc("dfsan mode"), cl::Hidden);

static cl::opt<bool> TrackMode("TrackMode", cl::desc("track mode"), cl::Hidden);

static cl::list<std::string> ClABIListFiles(
    "angora-dfsan-abilist",
    cl::desc("file listing native abi functions and how the pass treats them"),
    cl::Hidden);

static cl::list<std::string> ClExploitListFiles(
    "angora-exploitation-list",
    cl::desc("file listing functions and instructions to exploit"), cl::Hidden);

namespace {

#define MAX_EXPLOIT_CATEGORY 5
const char *ExploitCategoryAll = "all";
const char *ExploitCategory[] = {"i0", "i1", "i2", "i3", "i4"};
const char *CompareFuncCat = "cmpfn";

std::set<std::string> taint_targets;

// hash file name and file size
u32 hashName(std::string str) {
  std::ifstream in(str, std::ifstream::ate | std::ifstream::binary);
  u32 fsize = in.tellg();
  u32 hash = 5381 + fsize * 223;
  for (auto c : str)
    hash = ((hash << 5) + hash) + (unsigned char)c; /* hash * 33 + c */
  return hash;
}

class AngoraLLVMPass : public ModulePass {
public:
  static char ID;
  std::string ModName;
  u32 ModId;
  u32 CidCounter;
  unsigned long int RandSeed = 1;
  bool is_bc;
  unsigned int inst_ratio = 100;

  // Const Variables
  DenseSet<u32> UniqCidSet;

  // Configurations
  bool gen_id_random;
  bool output_cond_loc;
  int num_fn_ctx;

  MDNode *ColdCallWeights;

  // Types
  Type *VoidTy;
  IntegerType *Int1Ty;
  IntegerType *Int8Ty;
  IntegerType *Int16Ty;
  IntegerType *Int32Ty;
  IntegerType *Int64Ty;
  Type *Int8PtrTy;
  Type *Int64PtrTy;

  // Global vars
  GlobalVariable *AngoraMapPtr;
  GlobalVariable *AngoraPrevLoc;
  GlobalVariable *AngoraContext;
  GlobalVariable *AngoraCondId;
  GlobalVariable *AngoraCallSite;

  FunctionCallee TraceCmp;
  FunctionCallee TraceSw;
  FunctionCallee TraceCmpTT;
  FunctionCallee TraceTargetTT;
  FunctionCallee TraceSwTT;
  FunctionCallee TraceFnTT;
  FunctionCallee TraceExploitTT;

  // Custom setting
  AngoraABIList ABIList;
  AngoraABIList ExploitList;

  // Meta
  unsigned NoSanMetaId;
  MDTuple *NoneMetaNode;

  AngoraLLVMPass() : ModulePass(ID) {}
  bool runOnModule(Module &M) override;
  u32 getInstructionId(Instruction *Inst);
  u32 getRandomBasicBlockId();
  bool skipBasicBlock();
  u32 getRandomNum();
  void setRandomNumSeed(u32 seed);
  u32 getRandomContextId();
  u32 getRandomInstructionId();
  void setValueNonSan(Value *v);
  void setInsNonSan(Instruction *v);
  Value *castArgType(IRBuilder<> &IRB, Value *V);
  void initVariables(Module &M);
  void visitCallInst(Instruction *Inst,std::string location_str);
  void visitInvokeInst(Instruction *Inst,std::string location_str);
  void visitCompareFunc(Instruction *Inst,std::string location_str);
  void visitBranchInst(Instruction *Inst,std::string location_str);
  void visitCmpInst(Instruction *Inst,std::string location_str);
  void processCmp(Instruction *Cond, Constant *Cid, Instruction *InsertPoint,std::string location_str);
  void visitTargetInst(Instruction *Inst, std::string location_str);
  void processTarget(Instruction *Inst, Instruction *InsertPoint, std::string location_str);
  void processBoolCmp(Value *Cond, Constant *Cid, Instruction *InsertPoint,std::string location_str);
  void visitSwitchInst(Module &M, Instruction *Inst,std::string location_str);
  void visitExploitation(Instruction *Inst,std::string location_str);
  void processCall(Instruction *Inst,std::string location_str);
  void addFnWrap(Function &F);
};

} // namespace


void initTaintTarget(char* target_file) {
  std::string line;
  std::ifstream stream(target_file);

  while (std::getline(stream, line))
    taint_targets.insert(line);
}

char AngoraLLVMPass::ID = 0;

u32 AngoraLLVMPass::getRandomBasicBlockId() { return random() % MAP_SIZE; }

bool AngoraLLVMPass::skipBasicBlock() { return (random() % 100) >= inst_ratio; }

// http://pubs.opengroup.org/onlinepubs/009695399/functions/rand.html
u32 AngoraLLVMPass::getRandomNum() {
  RandSeed = RandSeed * 1103515245 + 12345;
  return (u32)RandSeed;
}

void AngoraLLVMPass::setRandomNumSeed(u32 seed) { RandSeed = seed; }

u32 AngoraLLVMPass::getRandomContextId() {
  u32 context = getRandomNum() % MAP_SIZE;
  if (output_cond_loc) {
    errs() << "[CONTEXT] " << context << "\n";
  }
  return context;
}

u32 AngoraLLVMPass::getRandomInstructionId() { return getRandomNum(); }

u32 AngoraLLVMPass::getInstructionId(Instruction *Inst) {
  u32 h = 0;
  if (is_bc) {
    h = ++CidCounter;
  } else {
    if (gen_id_random) {
      h = getRandomInstructionId();
    } else {
      DILocation *Loc = Inst->getDebugLoc();
      if (Loc) {
        u32 Line = Loc->getLine();
        u32 Col = Loc->getColumn();
        h = (Col * 33 + Line) * 33 + ModId;
      } else {
        h = getRandomInstructionId();
      }
    }

    while (UniqCidSet.count(h) > 0) {
      h = h * 3 + 1;
    }
    UniqCidSet.insert(h);
  }

  if (output_cond_loc) {
    errs() << "[ID] " << h << "\n";
    errs() << "[INS] " << *Inst << "\n";
    if (DILocation *Loc = Inst->getDebugLoc()) {
      errs() << "[LOC] " << cast<DIScope>(Loc->getScope())->getFilename()
             << ", Ln " << Loc->getLine() << ", Col " << Loc->getColumn()
             << "\n";
    }
  }

  return h;
}

void AngoraLLVMPass::setValueNonSan(Value *v) {
  if (Instruction *ins = dyn_cast<Instruction>(v))
    setInsNonSan(ins);
}

void AngoraLLVMPass::setInsNonSan(Instruction *ins) {
  if (ins)
    ins->setMetadata(NoSanMetaId, NoneMetaNode);
}

void AngoraLLVMPass::initVariables(Module &M) {
  // To ensure different version binaries have the same id
  ModName = M.getModuleIdentifier();
  if (ModName.size() == 0)
    FATAL("No ModName!\n");
  ModId = hashName(ModName);
  errs() << "ModName: " << ModName << " -- " << ModId << "\n";
  is_bc = 0 == ModName.compare(ModName.length() - 3, 3, ".bc");
  if (is_bc) {
    errs() << "Input is LLVM bitcode\n";
  }

  char *inst_ratio_str = getenv("ANGORA_INST_RATIO");
  if (inst_ratio_str) {
    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of ANGORA_INST_RATIO (must be between 1 and 100)");
  }
  errs() << "inst_ratio: " << inst_ratio << "\n";

  // set seed
  srandom(ModId);
  setRandomNumSeed(ModId);
  CidCounter = 0;

  LLVMContext &C = M.getContext();
  VoidTy = Type::getVoidTy(C);
  Int1Ty = IntegerType::getInt1Ty(C);
  Int8Ty = IntegerType::getInt8Ty(C);
  Int32Ty = IntegerType::getInt32Ty(C);
  Int64Ty = IntegerType::getInt64Ty(C);
  Int8PtrTy = PointerType::getUnqual(Int8Ty);
  Int64PtrTy = PointerType::getUnqual(Int64Ty);

  ColdCallWeights = MDBuilder(C).createBranchWeights(1, 1000);

  NoSanMetaId = C.getMDKindID("nosanitize");
  NoneMetaNode = MDNode::get(C, None);

  AngoraContext =
      new GlobalVariable(M, Int32Ty, false, GlobalValue::CommonLinkage,
                         ConstantInt::get(Int32Ty, 0), "__angora_context", 0,
                         GlobalVariable::GeneralDynamicTLSModel, 0, false);

  AngoraCallSite =
      new GlobalVariable(M, Int32Ty, false, GlobalValue::CommonLinkage,
                         ConstantInt::get(Int32Ty, 0), "__angora_call_site", 0,
                         GlobalVariable::GeneralDynamicTLSModel, 0, false);

    GET_OR_INSERT_FUNCTION(
        TraceCmpTT, VoidTy, "__angora_trace_cmp_tt",
        {Int32Ty, Int32Ty, Int32Ty, Int32Ty, Int64Ty, Int64Ty, Int32Ty})
    GET_OR_INSERT_FUNCTION(
        TraceTargetTT, VoidTy, "__angora_trace_target_tt",
        {Int64Ty, Int64Ty, Int8PtrTy})
    GET_OR_INSERT_FUNCTION(
        TraceSwTT, VoidTy, "__angora_trace_switch_tt",
        {Int32Ty, Int32Ty, Int32Ty, Int64Ty, Int32Ty, Int64PtrTy})
    GET_OR_INSERT_FUNCTION(TraceFnTT, VoidTy, "__angora_trace_fn_tt",
                           {Int32Ty, Int32Ty, Int32Ty, Int8PtrTy, Int8PtrTy})
    GET_OR_INSERT_FUNCTION(TraceExploitTT, VoidTy,
                           "__angora_trace_exploit_val_tt",
                           {Int32Ty, Int32Ty, Int32Ty, Int32Ty, Int64Ty})

  std::vector<std::string> AllABIListFiles;
  AllABIListFiles.insert(AllABIListFiles.end(), ClABIListFiles.begin(),
                         ClABIListFiles.end());
  ABIList.set(
      SpecialCaseList::createOrDie(AllABIListFiles, *vfs::getRealFileSystem()));

  std::vector<std::string> AllExploitListFiles;
  AllExploitListFiles.insert(AllExploitListFiles.end(),
                             ClExploitListFiles.begin(),
                             ClExploitListFiles.end());
  ExploitList.set(SpecialCaseList::createOrDie(AllExploitListFiles,
                                               *vfs::getRealFileSystem()));

  gen_id_random = !!getenv(GEN_ID_RANDOM_VAR);
  output_cond_loc = !!getenv(OUTPUT_COND_LOC_VAR);

  num_fn_ctx = -1;
  char *custom_fn_ctx = getenv(CUSTOM_FN_CTX);
  if (custom_fn_ctx) {
    num_fn_ctx = atoi(custom_fn_ctx);
    if (num_fn_ctx < 0 || num_fn_ctx >= 32) {
      errs() << "custom context should be: >= 0 && < 32 \n";
      exit(1);
    }
  }

  if (num_fn_ctx == 0) {
    errs() << "disable context\n";
  }

  if (num_fn_ctx > 0) {
    errs() << "use custom function call context: " << num_fn_ctx << "\n";
  }

  if (gen_id_random) {
    errs() << "generate id randomly\n";
  }

  if (output_cond_loc) {
    errs() << "Output cond log\n";
  }
};

void AngoraLLVMPass::addFnWrap(Function &F) {

  if (num_fn_ctx == 0)
    return;

  // *** Pre Fn ***
  BasicBlock *BB = &F.getEntryBlock();
  Instruction *InsertPoint = &(*(BB->getFirstInsertionPt()));
  IRBuilder<> IRB(InsertPoint);

  Value *CallSite = IRB.CreateLoad(AngoraCallSite);
  setValueNonSan(CallSite);

  Value *OriCtxVal = IRB.CreateLoad(AngoraContext);
  setValueNonSan(OriCtxVal);

  // ***** Add Context *****
  // instrument code before and after each function call to add context
  // We did `xor` simply.
  // This can avoid recursion. The effect of call in recursion will be removed
  // by `xor` with the same value
  // Implementation of function context for AFL by heiko eissfeldt:
  // https://github.com/vanhauser-thc/afl-patches/blob/master/afl-fuzz-context_sensitive.diff
  if (num_fn_ctx > 0) {
    OriCtxVal = IRB.CreateLShr(OriCtxVal, 32 / num_fn_ctx);
    setValueNonSan(OriCtxVal);
  }

  Value *UpdatedCtx = IRB.CreateXor(OriCtxVal, CallSite);
  setValueNonSan(UpdatedCtx);

  StoreInst *SaveCtx = IRB.CreateStore(UpdatedCtx, AngoraContext);
  setInsNonSan(SaveCtx);

  // *** Post Fn ***
  for (auto bb = F.begin(); bb != F.end(); bb++) {
    BasicBlock *BB = &(*bb);
    Instruction *Inst = BB->getTerminator();
    if (isa<ReturnInst>(Inst) || isa<ResumeInst>(Inst)) {
      // ***** Reload Context *****
      IRBuilder<> Post_IRB(Inst);
      Post_IRB.CreateStore(OriCtxVal, AngoraContext)
          ->setMetadata(NoSanMetaId, NoneMetaNode);
    }
  }
}

void AngoraLLVMPass::processCall(Instruction *Inst, std::string location_str) {

  visitCompareFunc(Inst,location_str);
  visitExploitation(Inst,location_str);

  //  if (ABIList.isIn(*Callee, "uninstrumented"))
  //  return;
  if (num_fn_ctx != 0) {
    IRBuilder<> IRB(Inst);
    Constant *CallSite = ConstantInt::get(Int32Ty, getRandomContextId());
    IRB.CreateStore(CallSite, AngoraCallSite)
        ->setMetadata(NoSanMetaId, NoneMetaNode);
  }
}

void AngoraLLVMPass::visitCallInst(Instruction *Inst,std::string location_str) {

  CallInst *Caller = dyn_cast<CallInst>(Inst);
  Function *Callee = Caller->getCalledFunction();

  if (!Callee || Callee->isIntrinsic() ||
      isa<InlineAsm>(Caller->getCalledOperand())) {
    return;
  }

  // remove inserted "unfold" functions
  if (!Callee->getName().compare(StringRef("__unfold_branch_fn"))) {
    if (Caller->use_empty()) {
      Caller->eraseFromParent();
    }
    return;
  }

  processCall(Inst, location_str);
};

void AngoraLLVMPass::visitInvokeInst(Instruction *Inst,std::string location_str) {

  InvokeInst *Caller = dyn_cast<InvokeInst>(Inst);
  Function *Callee = Caller->getCalledFunction();

  if (!Callee || Callee->isIntrinsic() ||
      isa<InlineAsm>(Caller->getCalledOperand())) {
    return;
  }

  processCall(Inst,location_str);
}

void AngoraLLVMPass::visitCompareFunc(Instruction *Inst,std::string location_str) {
  // configuration file: custom/exploitation_list.txt  fun:xx=cmpfn

  if (!isa<CallInst>(Inst) || !ExploitList.isIn(*Inst, CompareFuncCat)) {
    return;
  }
  ConstantInt *Cid = ConstantInt::get(Int32Ty, getInstructionId(Inst));

  if (!TrackMode)
    return;

  CallInst *Caller = dyn_cast<CallInst>(Inst);
  Value *OpArg[2];
  OpArg[0] = Caller->getArgOperand(0);
  OpArg[1] = Caller->getArgOperand(1);

  if (!OpArg[0]->getType()->isPointerTy() ||
      !OpArg[1]->getType()->isPointerTy()) {
    return;
  }

  Value *ArgSize = nullptr;
  if (Caller->getNumArgOperands() > 2) {
    ArgSize = Caller->getArgOperand(2); // int32ty
  } else {
    ArgSize = ConstantInt::get(Int32Ty, 0);
  }

  IRBuilder<> IRB(Inst);
  LoadInst *CurCtx = IRB.CreateLoad(AngoraContext);
  setInsNonSan(CurCtx);
  CallInst *ProxyCall =
      IRB.CreateCall(TraceFnTT, {Cid, CurCtx, ArgSize, OpArg[0], OpArg[1]});
  setInsNonSan(ProxyCall);
}

Value *AngoraLLVMPass::castArgType(IRBuilder<> &IRB, Value *V) {
  Type *OpType = V->getType();
  Value *NV = V;
  if (OpType->isFloatTy()) {
    NV = IRB.CreateFPToUI(V, Int32Ty);
    setValueNonSan(NV);
    NV = IRB.CreateIntCast(NV, Int64Ty, false);
    setValueNonSan(NV);
  } else if (OpType->isDoubleTy()) {
    NV = IRB.CreateFPToUI(V, Int64Ty);
    setValueNonSan(NV);
  } else if (OpType->isPointerTy()) {
    NV = IRB.CreatePtrToInt(V, Int64Ty);
  } else {
    if (OpType->isIntegerTy() && OpType->getIntegerBitWidth() < 64) {
      NV = IRB.CreateZExt(V, Int64Ty);
    }
  }
  return NV;
}

void AngoraLLVMPass::processCmp(Instruction *Cond, Constant *Cid,
                                Instruction *InsertPoint,std::string location_str) {
  CmpInst *Cmp = dyn_cast<CmpInst>(Cond);
  Value *OpArg[2];
  OpArg[0] = Cmp->getOperand(0);
  OpArg[1] = Cmp->getOperand(1);
  Type *OpType = OpArg[0]->getType();
  if (!((OpType->isIntegerTy() && OpType->getIntegerBitWidth() <= 64) ||
        OpType->isFloatTy() || OpType->isDoubleTy() || OpType->isPointerTy())) {
    processBoolCmp(Cond, Cid, InsertPoint,location_str);
    return;
  }
  int num_bytes = OpType->getScalarSizeInBits() / 8;
  if (num_bytes == 0) {
    if (OpType->isPointerTy()) {
      num_bytes = 8;
    } else {
      return;
    }
  }

  IRBuilder<> IRB(InsertPoint);

    Value *SizeArg = ConstantInt::get(Int32Ty, num_bytes);
    u32 predicate = Cmp->getPredicate();
    if (ConstantInt *CInt = dyn_cast<ConstantInt>(OpArg[1])) {
      if (CInt->isNegative()) {
        predicate |= COND_SIGN_MASK;
      }
    }
    Value *TypeArg = ConstantInt::get(Int32Ty, predicate);
    Value *CondExt = IRB.CreateZExt(Cond, Int32Ty);
    setValueNonSan(CondExt);
    OpArg[0] = castArgType(IRB, OpArg[0]);
    OpArg[1] = castArgType(IRB, OpArg[1]);
    Value *Str = IRB.CreateGlobalStringPtr(location_str.c_str());
    LoadInst *CurCtx = IRB.CreateLoad(AngoraContext);
    setInsNonSan(CurCtx);
    CallInst *ProxyCall =
        IRB.CreateCall(TraceCmpTT, {Cid, CurCtx, SizeArg, TypeArg, OpArg[0],
                                    OpArg[1], CondExt, Str});
    setInsNonSan(ProxyCall);

}

void AngoraLLVMPass::processBoolCmp(Value *Cond, Constant *Cid,
                                    Instruction *InsertPoint,std::string location_str) {
  if (!Cond->getType()->isIntegerTy() ||
      Cond->getType()->getIntegerBitWidth() > 32)
    return;
  Value *OpArg[2];
  OpArg[1] = ConstantInt::get(Int64Ty, 1);
  IRBuilder<> IRB(InsertPoint);

    Value *SizeArg = ConstantInt::get(Int32Ty, 1);
    Value *TypeArg = ConstantInt::get(Int32Ty, COND_EQ_OP | COND_BOOL_MASK);
    Value *CondExt = IRB.CreateZExt(Cond, Int32Ty);
    setValueNonSan(CondExt);
    OpArg[0] = IRB.CreateZExt(CondExt, Int64Ty);
    setValueNonSan(OpArg[0]);
    LoadInst *CurCtx = IRB.CreateLoad(AngoraContext);
    setInsNonSan(CurCtx);
    Value *Str = IRB.CreateGlobalStringPtr(location_str.c_str());
    CallInst *ProxyCall =
        IRB.CreateCall(TraceCmpTT, {Cid, CurCtx, SizeArg, TypeArg, OpArg[0],
                                    OpArg[1], CondExt,Str});
    setInsNonSan(ProxyCall);
  
}

void AngoraLLVMPass::visitCmpInst(Instruction *Inst,std::string location_str) {
  Instruction *InsertPoint = Inst->getNextNode();
  if (!InsertPoint || isa<ConstantInt>(Inst))
    return;
  Constant *Cid = ConstantInt::get(Int32Ty, getInstructionId(Inst));
  processCmp(Inst, Cid, InsertPoint, location_str);
}

void AngoraLLVMPass::processTarget(Instruction *Inst, Instruction *InsertPoint, std::string location_str) {
  // CmpInst *Cmp = dyn_cast<CmpInst>(Inst);

  int num_operand = Inst->getNumOperands();

  Value *OpArg[2];
  OpArg[0] = Inst->getOperand(0);
  
  if (num_operand > 1)
    OpArg[1] = Inst->getOperand(1);
  else
    OpArg[1] = Inst->getOperand(0);

  IRBuilder<> IRB(InsertPoint);


  OpArg[0] = castArgType(IRB, OpArg[0]);
  OpArg[1] = castArgType(IRB, OpArg[1]);
  Value *Str = IRB.CreateGlobalStringPtr(location_str.c_str());
  CallInst *ProxyCall =
      IRB.CreateCall(TraceTargetTT, {OpArg[0],
                                  OpArg[1], Str});
  setInsNonSan(ProxyCall);

}

void AngoraLLVMPass::visitTargetInst(Instruction *Inst, std::string location_str) {
  Instruction *InsertPoint = Inst->getNextNode();
  if (!InsertPoint || isa<ConstantInt>(Inst))
    return;
  // Constant *Cid = ConstantInt::get(Int32Ty, getInstructionId(Inst));
  processTarget(Inst, InsertPoint, location_str);
}

void AngoraLLVMPass::visitBranchInst(Instruction *Inst,std::string location_str) {
  BranchInst *Br = dyn_cast<BranchInst>(Inst);
  if (Br->isConditional()) {
    Value *Cond = Br->getCondition();
    if (Cond && Cond->getType()->isIntegerTy() && !isa<ConstantInt>(Cond)) {
      if (!isa<CmpInst>(Cond)) {
        // From  and, or, call, phi ....
        Constant *Cid = ConstantInt::get(Int32Ty, getInstructionId(Inst));
        processBoolCmp(Cond, Cid, Inst, location_str);
      }
    }
  }
}

void AngoraLLVMPass::visitSwitchInst(Module &M, Instruction *Inst,std::string location_str) {

  SwitchInst *Sw = dyn_cast<SwitchInst>(Inst);
  Value *Cond = Sw->getCondition();

  if (!(Cond && Cond->getType()->isIntegerTy() && !isa<ConstantInt>(Cond))) {
    return;
  }

  int num_bits = Cond->getType()->getScalarSizeInBits();
  int num_bytes = num_bits / 8;
  if (num_bytes == 0 || num_bits % 8 > 0)
    return;

  Constant *Cid = ConstantInt::get(Int32Ty, getInstructionId(Inst));
  IRBuilder<> IRB(Sw);

    Value *SizeArg = ConstantInt::get(Int32Ty, num_bytes);
    SmallVector<Constant *, 16> ArgList;
    for (auto It : Sw->cases()) {
      Constant *C = It.getCaseValue();
      if (C->getType()->getScalarSizeInBits() > Int64Ty->getScalarSizeInBits())
        continue;
      ArgList.push_back(ConstantExpr::getCast(CastInst::ZExt, C, Int64Ty));
    }

    ArrayType *ArrayOfInt64Ty = ArrayType::get(Int64Ty, ArgList.size());
    GlobalVariable *ArgGV = new GlobalVariable(
        M, ArrayOfInt64Ty, false, GlobalVariable::InternalLinkage,
        ConstantArray::get(ArrayOfInt64Ty, ArgList),
        "__angora_switch_arg_values");
    Value *SwNum = ConstantInt::get(Int32Ty, ArgList.size());
    Value *ArrPtr = IRB.CreatePointerCast(ArgGV, Int64PtrTy);
    setValueNonSan(ArrPtr);
    Value *CondExt = IRB.CreateZExt(Cond, Int64Ty);
    setValueNonSan(CondExt);
    LoadInst *CurCtx = IRB.CreateLoad(AngoraContext);
    setInsNonSan(CurCtx);
    CallInst *ProxyCall = IRB.CreateCall(
        TraceSwTT, {Cid, CurCtx, SizeArg, CondExt, SwNum, ArrPtr});
    setInsNonSan(ProxyCall);
}

void AngoraLLVMPass::visitExploitation(Instruction *Inst,std::string location_str) {
  // For each instruction and called function.
  bool exploit_all = ExploitList.isIn(*Inst, ExploitCategoryAll);
  IRBuilder<> IRB(Inst);
  int numParams = Inst->getNumOperands();
  CallInst *Caller = dyn_cast<CallInst>(Inst);

  if (Caller) {
    numParams = Caller->getNumArgOperands();
  }

  Value *TypeArg =
      ConstantInt::get(Int32Ty, COND_EXPLOIT_MASK | Inst->getOpcode());

  for (int i = 0; i < numParams && i < MAX_EXPLOIT_CATEGORY; i++) {
    if (exploit_all || ExploitList.isIn(*Inst, ExploitCategory[i])) {
      Value *ParamVal = NULL;
      if (Caller) {
        ParamVal = Caller->getArgOperand(i);
      } else {
        ParamVal = Inst->getOperand(i);
      }
      Type *ParamType = ParamVal->getType();
      if (ParamType->isIntegerTy() || ParamType->isPointerTy()) {
        if (!isa<ConstantInt>(ParamVal)) {
          ConstantInt *Cid = ConstantInt::get(Int32Ty, getInstructionId(Inst));
          int size = ParamVal->getType()->getScalarSizeInBits() / 8;
          if (ParamType->isPointerTy()) {
            size = 8;
            // Hardware-wise, a pointer is an int64, no big deal.
            // This explict cast is to make llvm backend happy.
            ParamVal = IRB.CreatePtrToInt(ParamVal, Int64Ty);
          } else if (!ParamType->isIntegerTy(64)) {
            ParamVal = IRB.CreateZExt(ParamVal, Int64Ty);
          }
          Value *SizeArg = ConstantInt::get(Int32Ty, size);
          Value *Str = IRB.CreateGlobalStringPtr(location_str.c_str());
          if (TrackMode) {
            LoadInst *CurCtx = IRB.CreateLoad(AngoraContext);
            setInsNonSan(CurCtx);
            CallInst *ProxyCall = IRB.CreateCall(
                TraceExploitTT, {Cid, CurCtx, SizeArg, TypeArg, ParamVal,Str});
            setInsNonSan(ProxyCall);
          }
        }
      }
    }
  }
}

bool AngoraLLVMPass::runOnModule(Module &M) {

  SAYF(cCYA "angora-llvm-pass\n");
  if (TrackMode) {
    OKF("Track Mode.");
  } else if (DFSanMode) {
    OKF("DFSan Mode.");
  }

  for (auto &F : M) {
      F.addFnAttr("dfs");
  }

  initVariables(M);

  char* target_file = getenv("ANGORA_TAINT_TARGET");
  initTaintTarget(target_file);

  if (DFSanMode)
    return true;

  for (auto &F : M) {
    if (F.isDeclaration() || F.getName().startswith(StringRef("asan.module")))
      continue;

    // get file name from function.
    std::string file_name;
    if (auto *SP = F.getSubprogram()) {
        file_name = SP->getFilename().str();
    }
    // Keep only the file name.
    std::size_t tokloc = file_name.find_last_of('/');
    if (tokloc != std::string::npos) {
      file_name = file_name.substr(tokloc + 1, std::string::npos);
    }

    addFnWrap(F);

    std::vector<BasicBlock *> bb_list;
    for (auto bb = F.begin(); bb != F.end(); bb++)
      bb_list.push_back(&(*bb));

    for (auto bi = bb_list.begin(); bi != bb_list.end(); bi++) {
      BasicBlock *BB = *bi;
      std::vector<Instruction *> inst_list;

      for (auto inst = BB->begin(); inst != BB->end(); inst++) {
        Instruction *Inst = &(*inst);
        inst_list.push_back(Inst);
      }

      for (auto inst = inst_list.begin(); inst != inst_list.end(); inst++) {
        Instruction *Inst = *inst;

        // Check and skip the LLVM intrinsic instructions.
        if (auto *II = dyn_cast<IntrinsicInst>(Inst)) {
            if (II->getIntrinsicID() == Intrinsic::dbg_declare) {
                continue;
            }
        }
        // Skip PHI instructions
        if (isa<PHINode>(Inst)) {
            continue;
        }
        // Skip instructions with no metadata
        if (Inst->getMetadata(NoSanMetaId))
          continue;
        
        // Get the line number of the instruction.
        DebugLoc dbg = (*inst)->getDebugLoc();
        DILocation* DILoc = dbg.get();
        if (!DILoc || !DILoc->getLine()) 
          continue; 
        std::string line_str = std::to_string(DILoc->getLine());
        std::string location_str = file_name + std::string(":") + line_str;

        std::set<std::string>::iterator it;
        for (it = taint_targets.begin(); it != taint_targets.end(); ++it) {
          if (location_str.compare(*it) == 0) {
            std::cerr << "@@ " << location_str << ": ";
            errs() << *Inst << "\n";
            visitTargetInst(Inst, location_str);
            break;
          }
        }
      }
    }
  }

  // Print the ll file with name angora.ll
  std::string ll_file = "angora.ll";
  std::error_code EC;
  raw_fd_ostream OS(ll_file, EC, sys::fs::F_None);
  M.print(OS, nullptr);
  OS.close();

  std::cout << "The ll file is saved as angora.ll" << std::endl;


  if (is_bc)
    OKF("Max constraint id is %d", CidCounter);
  return true;
}

static void registerAngoraLLVMPass(const PassManagerBuilder &,
                                   legacy::PassManagerBase &PM) {
  PM.add(new AngoraLLVMPass());
}

static RegisterPass<AngoraLLVMPass> X("angora_llvm_pass", "Angora LLVM Pass",
                                      false, false);

static RegisterStandardPasses
    RegisterAngoraLLVMPass(PassManagerBuilder::EP_OptimizerLast,
                           registerAngoraLLVMPass);
static RegisterStandardPasses
    RegisterAngoraLLVMPass0(PassManagerBuilder::EP_EnabledOnOptLevel0,
                            registerAngoraLLVMPass);