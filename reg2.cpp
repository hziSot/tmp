#include <iostream>
#include <capstone/capstone.h>

#define DECLARE_RETURN_X(__reg__, __shift__, __mask__) \
    return (__reg__ >> (__shift__)) & (__mask__)

#define DECLARE_CASE_RETURN(__r__, __R__, __shift__, __mask__) \
    case X86_REG_ ## __R__ : DECLARE_RETURN_X(__r__, __shift__, __mask__);

#define DECLARE_CASE_RETURN_X(__x__, __X__) \
    DECLARE_CASE_RETURN(__x__, R ## __X__ ## X, 0, -1UL); \
    DECLARE_CASE_RETURN(__x__, E ## __X__ ## X, 0, (1UL << 32) - 1); \
    DECLARE_CASE_RETURN(__x__, __X__ ## X, 0, (1UL << 16) - 1); \
    DECLARE_CASE_RETURN(__x__, __X__ ## H, 8, (1UL << 8) - 1); \
    DECLARE_CASE_RETURN(__x__, __X__ ## L, 0, (1UL << 8) - 1)

#define DECLARE_CASE_RETURN_R(__x__, __N__) \
    DECLARE_CASE_RETURN(__x__, __N__, 0, -1UL); \
    DECLARE_CASE_RETURN(__x__, __N__ ## D, 0, (1UL << 32) - 1); \
    DECLARE_CASE_RETURN(__x__, __N__ ## W, 0, (1UL << 16) - 1); \
    DECLARE_CASE_RETURN(__x__, __N__ ## B, 0, (1UL << 8) - 1);

#define DECLARE_CASE_RETURN_IP(__x__, __X__) \
    DECLARE_CASE_RETURN(__x__, R ## __X__, 0, -1UL); \
    DECLARE_CASE_RETURN(__x__, E ## __X__, 0, (1UL << 32) - 1); \
    DECLARE_CASE_RETURN(__x__, __X__, 0, (1UL << 16) - 1);

#define DECLARE_ASSIGN_X(__reg__, __shift__, __mask__, v) \
    /*                 clean space of __reg__          /      emplace register         */ \
    __reg__ = (__reg__ & (~((__mask__) << __shift__))) | (((v) & (__mask__)) << (__shift__))

#define DECLARE_CASE_ASSIGN(__r__, __R__, __shift__, __mask__, v) \
    case X86_REG_ ## __R__ : DECLARE_ASSIGN_X(__r__, __shift__, __mask__, v); break

#define DECLARE_CASE_ASSIGN_X(__x__, __X__, v) \
    DECLARE_CASE_ASSIGN(__x__, R ## __X__ ## X, 0, -1UL, v); \
    DECLARE_CASE_ASSIGN(__x__, E ## __X__ ## X, 0, (1UL << 32) - 1, v); \
    DECLARE_CASE_ASSIGN(__x__, __X__ ## X, 0, (1UL << 16) - 1, v); \
    DECLARE_CASE_ASSIGN(__x__, __X__ ## H, 8, (1UL << 8) - 1, v); \
    DECLARE_CASE_ASSIGN(__x__, __X__ ## L, 0, (1UL << 8) - 1, v)

#define DECLARE_CASE_ASSIGN_R(__x__, __N__, v) \
    DECLARE_CASE_ASSIGN(__x__, __N__, 0, -1UL, v); \
    DECLARE_CASE_ASSIGN(__x__, __N__ ## D, 0, (1UL << 32) - 1, v); \
    DECLARE_CASE_ASSIGN(__x__, __N__ ## W, 0, (1UL << 16) - 1, v); \
    DECLARE_CASE_ASSIGN(__x__, __N__ ## B, 0, (1UL << 8) - 1, v);

#define DECLARE_CASE_ASSIGN_IP(__x__, __X__, v) \
    DECLARE_CASE_ASSIGN(__x__, R ## __X__, 0, -1UL, v); \
    DECLARE_CASE_ASSIGN(__x__, E ## __X__, 0, (1UL << 32) - 1, v); \
    DECLARE_CASE_ASSIGN(__x__, __X__, 0, (1UL << 16) - 1, v);


struct pt_regs {
    uint64_t r15, r14, r13, r12, rbp, rbx;
    uint64_t r11, r10, r9, r8, rax, rcx;
    uint64_t rdx ,rsi, rdi, orig_ax;
    uint64_t rip, cs, flags, rsp, ss;
    uint64_t get(enum x86_reg reg)
    {
        switch (reg) {
            DECLARE_CASE_RETURN_X(rax, A);
            DECLARE_CASE_RETURN_X(rbx, B);
            DECLARE_CASE_RETURN_X(rcx, C);
            DECLARE_CASE_RETURN_X(rdx, D);
            DECLARE_CASE_RETURN_R(r8, R8);
            DECLARE_CASE_RETURN_R(r9, R9);
            DECLARE_CASE_RETURN_R(r10, R10);
            DECLARE_CASE_RETURN_R(r11, R11);
            DECLARE_CASE_RETURN_R(r12, R12);
            DECLARE_CASE_RETURN_R(r13, R13);
            DECLARE_CASE_RETURN_R(r14, R14);
            DECLARE_CASE_RETURN_R(r15, R15);
            DECLARE_CASE_RETURN_IP(rbp, BP);
            DECLARE_CASE_RETURN_IP(rsp, SP);
            DECLARE_CASE_RETURN_IP(rdi, DI);
            DECLARE_CASE_RETURN_IP(rsi, SI);
            default: return 0;
        }
    }
    void set(enum x86_reg reg, uint64_t v)
    {
        switch (reg) {
            DECLARE_CASE_ASSIGN_X(rax, A, v);
            DECLARE_CASE_ASSIGN_X(rbx, B, v);
            DECLARE_CASE_ASSIGN_X(rcx, C, v);
            DECLARE_CASE_ASSIGN_X(rdx, D, v);
            DECLARE_CASE_ASSIGN_R(r8, R8, v);
            DECLARE_CASE_ASSIGN_R(r9, R9, v);
            DECLARE_CASE_ASSIGN_R(r10, R10, v);
            DECLARE_CASE_ASSIGN_R(r11, R11, v);
            DECLARE_CASE_ASSIGN_R(r12, R12, v);
            DECLARE_CASE_ASSIGN_R(r13, R13, v);
            DECLARE_CASE_ASSIGN_R(r14, R14, v);
            DECLARE_CASE_ASSIGN_R(r15, R15, v);
            DECLARE_CASE_ASSIGN_IP(rbp, BP, v);
            DECLARE_CASE_ASSIGN_IP(rsp, SP, v);
            DECLARE_CASE_ASSIGN_IP(rdi, DI, v);
            DECLARE_CASE_ASSIGN_IP(rsi, SI, v);
            default: break;
        }
    }

};

void display_pt_regs(const struct pt_regs& r)
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
            r.rip, r.flags,
            r.cs, r.ss,
            r.rsp, r.rbp, r.rsi, r.rdi,
            r.rax, r.rbx, r.rcx, r.rdx,
            r.r8, r.r9, r.r10, r.r11,
            r.r12, r.r13, r.r14, r.r15);
}

int main(void) {
    struct pt_regs regs{};
    regs.rax = 0xffeeddccbbaa9988;
    std::cout << std::hex 
        << "rax: " << regs.rax << std::endl
        << "eax: " << regs.get(X86_REG_EAX) << std::endl
        << "ax: " << regs.get(X86_REG_AX)<< std::endl
        << "ah: " << regs.get(X86_REG_AH) << std::endl
        << "al: " << regs.get(X86_REG_AL) << std::endl;
    regs.set(X86_REG_EAX, 0xdeadbeef);
    std::cout << std::hex 
        << "rax: " << regs.rax << std::endl
        << "eax: " << regs.get(X86_REG_EAX) << std::endl
        << "ax: " << regs.get(X86_REG_AX)<< std::endl
        << "ah: " << regs.get(X86_REG_AH) << std::endl
        << "al: " << regs.get(X86_REG_AL) << std::endl;
    regs.set(X86_REG_AH, 0xde);
    std::cout << std::hex 
        << "rax: " << regs.rax << std::endl
        << "eax: " << regs.get(X86_REG_EAX) << std::endl
        << "ax: " << regs.get(X86_REG_AX)<< std::endl
        << "ah: " << regs.get(X86_REG_AH) << std::endl
        << "al: " << regs.get(X86_REG_AL) << std::endl;
    regs.set(X86_REG_AL, 0xaf);
    std::cout << std::hex 
        << "rax: " << regs.rax << std::endl
        << "eax: " << regs.get(X86_REG_EAX) << std::endl
        << "ax: " << regs.get(X86_REG_AX)<< std::endl
        << "ah: " << regs.get(X86_REG_AH) << std::endl
        << "al: " << regs.get(X86_REG_AL) << std::endl;

    display_pt_regs(regs);

}
