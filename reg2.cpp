#include <capstone/capstone.h>
#include <cstdint>
#include <iostream>

#define RCRD(__R__, __mask__, __offset__, __shift__) \
    __types[X86_REG_ ## __R__] = {__mask__, __offset__, __shift__}

#define RCRD_ALL(__R8__, __R16__, __R32__, __R64__, __OFFR__) \
    RCRD(__R8__,  0xff, OFF_ ## __OFFR__, 0); \
    RCRD(__R16__, 0xffff, OFF_ ## __OFFR__, 0); \
    RCRD(__R32__, 0xffffffff, OFF_ ## __OFFR__, 0); \
    RCRD(__R64__, 0xffffffffffffffff, OFF_ ## __OFFR__, 0)

#define RCRD_ALL_X(__RL__, __OFFR__) \
    RCRD(__RL__ ## H, 0xff, OFF_ ## __OFFR__, 8); \
    RCRD_ALL(__RL__ ## L, __RL__ ## X, E ## __RL__ ## X, R ## __RL__ ## X, __OFFR__)

#define RCRD_ALL_R(__RL__, __OFFR__) \
    RCRD_ALL(__RL__ ## B, __RL__ ## W, __RL__ ## D, __RL__ , __OFFR__)

#define RCRD_ALL_IP(__RL__, __OFFR__) \
    RCRD_ALL(__RL__ ## L, __RL__, E ## __RL__ , R ## __RL__ , __OFFR__)

struct pt_regs {
    uint64_t r15, r14, r13, r12, rbp, rbx;
    uint64_t r11, r10, r9, r8, rax, rcx;
    uint64_t rdx ,rsi, rdi, orig_ax;
    uint64_t rip, cs, flags, rsp, ss;
};

class registers {
        enum register_offset {
            OFF_R15 = 0, OFF_R14, OFF_R13, OFF_R12, OFF_RBP, OFF_RBX, OFF_R11,
            OFF_R10, OFF_R9, OFF_R8 , OFF_RAX, OFF_RCX, OFF_RDX, OFF_RSI,
            OFF_RDI, OFF_ORIG_AX, OFF_RIP, OFF_CS, OFF_RFLAGS, OFF_RSP, OFF_SS
        };
        struct register_type {
            uint64_t mask;
            uint16_t offset, shift;
        };

    public:
        registers() : __regs{} {
            RCRD_ALL_X(A, RAX); RCRD_ALL_X(B, RBX); RCRD_ALL_X(C, RCX);
            RCRD_ALL_X(D, RDX); RCRD_ALL_R(R8, R8); RCRD_ALL_R(R9, R9);
            RCRD_ALL_R(R10, R10); RCRD_ALL_R(R11, R11); RCRD_ALL_R(R12, R12);
            RCRD_ALL_R(R13, R13); RCRD_ALL_R(R14, R14); RCRD_ALL_R(R15, R15);
            RCRD_ALL_IP(BP, RBP); RCRD_ALL_IP(SP, RSP); RCRD_ALL_IP(DI, RDI);
            RCRD_ALL_IP(SI, RSI); RCRD(RIP, 0xffffffffffffffff, OFF_RIP, 0);
        }
        uint64_t get(enum x86_reg reg) const
        {
            const auto& type = __types[reg];
            return (__regs[type.offset] >> type.shift) & type.mask;
        }
        void set(enum x86_reg reg, uint64_t v)
        {
            const auto& type = __types[reg];
            auto& r = __regs[type.offset];
            r = r & (~(type.mask << type.shift)); // clean space
            r |= ((v & type.mask) << type.shift); // emplace value
        }
        const struct pt_regs* pt_regs(void) const
        { return &__pt_regs; }
        
    private:
        struct register_type __types[X86_REG_ENDING];
        union {
            uint64_t __regs[21];
            struct pt_regs __pt_regs;
        };
};


void display_pt_regs(const struct pt_regs* r)
{
    std::printf("         RIP: %016lx       RFLAGS: %08lx\n"
            "          CS: %04lx    SS: %04lx\n"
            "         RSP: %016lx       RBP: %016lx\n"
            "         RSI: %016lx       RDI: %016lx\n"
            "         RAX: %016lx       RBX: %016lx\n"
            "         RCX: %016lx       RDX: %016lx\n"
            "          R8: %016lx        R9: %016lx\n"
            "         R10: %016lx       R11: %016lx\n"
            "         R12: %016lx       R13: %016lx\n"
            "         R14: %016lx       R15: %016lx\n",
            r->rip, r->flags,
            r->cs, r->ss,
            r->rsp, r->rbp, r->rsi, r->rdi,
            r->rax, r->rbx, r->rcx, r->rdx,
            r->r8, r->r9, r->r10, r->r11,
            r->r12, r->r13, r->r14, r->r15);
}


int main(void) {
    registers regs;

    regs.set(X86_REG_RAX, 0xffffffffffffffff);
    regs.set(X86_REG_RIP, 0xffffffffffffffff);
    regs.set(X86_REG_R15, 0xffffffffffffffff);
    regs.set(X86_REG_EAX, 0xdeadbeef);
    std::cout << std::hex 
        << "rax: " << regs.get(X86_REG_RAX) << std::endl
        << "eax: " << regs.get(X86_REG_EAX) << std::endl
        << "ax: " << regs.get(X86_REG_AX)<< std::endl
        << "ah: " << regs.get(X86_REG_AH) << std::endl
        << "al: " << regs.get(X86_REG_AL) << std::endl;
    regs.set(X86_REG_AH, 0xde);
    std::cout << std::hex 
        << "rax: " << regs.get(X86_REG_RAX) << std::endl
        << "eax: " << regs.get(X86_REG_EAX) << std::endl
        << "ax: " << regs.get(X86_REG_AX)<< std::endl
        << "ah: " << regs.get(X86_REG_AH) << std::endl
        << "al: " << regs.get(X86_REG_AL) << std::endl;
    regs.set(X86_REG_AL, 0xaf);
    std::cout << std::hex 
        << "rax: " << regs.get(X86_REG_RAX) << std::endl
        << "eax: " << regs.get(X86_REG_EAX) << std::endl
        << "ax: " << regs.get(X86_REG_AX)<< std::endl
        << "ah: " << regs.get(X86_REG_AH) << std::endl
        << "al: " << regs.get(X86_REG_AL) << std::endl;

    display_pt_regs(regs.pt_regs());
    return 0;
}

