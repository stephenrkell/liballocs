# We have a thread-local whose job is to store the real
# return address. Our trampoline will write into this
# immediately before it clobbers the on-stack return address.
    .globl  real_return_address
    .section        .tbss,"awT",@nobits
    .align 8
    .type   real_return_address, @object
    .size   real_return_address, 8
real_return_address:
    .zero   8

    .text
    .globl  generic_return_hook
    .type   generic_return_hook, @function
    .align 16
generic_return_hook:
    # We can treat %rdi as a scratch register because it's not callee-saved.
    pushq %rax
    # --- begin 16-byte TLS magic
        # .byte 0x66
        # leaq    real_return_address@tlsgd(%rip), %rdi
        # .word 0x6666
        # rex64 call    __tls_get_addr@plt
    # --- end 16-byte TLS magic
    # This "leaq; call" sequence will get turned into a "mov; lea" sequence
    # by the linker, if it knows that the sought TLS entry is module-local.
    # The initial 'mov' materialises the base address of the TLS block,
    # and the following 'lea' applies an offset that reaches the variable.
    # This pair of instructions are also 16 bytes.
    # Let's just include them directly.
         mov    %fs:0x0,%rax
         lea    real_return_address@tpoff(%rax),%rax
    movq %rax, %rdi  # TLS address is in %rdi now
    popq %rax    # Now %rax has its original value
    pushq (%rdi) # Now the saved return address is back on the stack
    # ___ <-- in here we can do what we like -- call to an outside helper?
    retq
# FIXME: write some DWARF CFI for this code.
# Can we set up the CFI s.t. it loads the
# return address from the TLS var just like we do?
# Obviously, that will no longer apply at the final 'retq'.
