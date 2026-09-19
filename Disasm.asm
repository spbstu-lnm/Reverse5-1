;------------------------------------------------------------------------------
;
;   Disasm.asm : anti-disassembly primitives
;
;   Assembled with MASM (ml64.exe). 
;   Must be included in CMakeLists.txt!
;
;   Both routines below are written by hand in assembly 
;   because C++ compiler will not produce code that leads to desync 
;   in linear disassembler.
;
;------------------------------------------------------------------------------

.code

;==============================================================================
;
; int asmJunkByteTrick(int x); --- x64 fastcall: x arrives in ECX
;
; Returns x unchanged. Technique: "jump over a junk opcode byte".
;
; Runtime behaviour:
;     jmp short j_skip     --> CPU jumps straight to j_skip, executes
;                              mov eax, ecx / ret. Correct result: eax == x.
;
; POV of linear disassembler if it ignores jmp target and just keeps decoding:
;
;     0E8h                 --> byte value 0E8h is the opcode for a 5-byte
;                              relative CALL (E8 + 4-byte displacement).
;                              The disassembler is now committed to
;                              consuming the following 4 bytes as that
;                              call's operand.
;
;     08Bh,0C1h,0C3h,090h  --> junk (machine code of two following instructions
;                              that gets decoded as rel32 operand of fake CALL
;
;==============================================================================

asmJunkByteTrick PROC
        jmp     short j_skip

        db      0E8h                      ; fake CALL opcode, never executed
        db      08Bh, 0C1h, 0C3h, 090h    ; == mov eax,ecx / ret / nop below,
                                          ; misread as the CALL's rel32 operand

j_skip:
        mov     eax, ecx                  ; what actually gets executed
        ret
        nop
asmJunkByteTrick ENDP


;==============================================================================
;
; const unsigned char* asmCallOverDataTrick(void);
;
; Returns a pointer to 10 bytes of XOR-obfuscated data ("PROTECTED" XORed
; byte-by-byte with 055h, including an XORed null-terminator). Technique:
; "call over data" --- using CALL purely to smuggle a data pointer, never
; intending the callee to RET back to the call site in the normal sense.
;
; Runtime behaviour:
;     call d_get   --> pushes the return address (the first byte of following 
;                      data) and jumps to d_get.
;     d_get:
;         pop rax  --> instead of returning through it, d_get simply pops
;                      that "return address" into RAX. RAX now holds a
;                      pointer to the data, obtained without a single
;                      RIP-relative LEA or any relocation a static tool
;                      could trivially flag as "this loads a string here".
;
;         ret      --> genuinely returns to asmCallOverDataTrick's caller.
;
; What a linear disassembler sees: `call d_get`, and then --- with nothing
; telling it otherwise --- it keeps decoding the FOLLOWING TEN BYTES as if
; they were more instructions of this same routine, because a plain
; linear/naive disassembler has no way to know that the "callee" never
; intends to return through the call site and that those ten bytes are
; data, not code. The resulting listing decodes ten bytes of essentially
; random-looking data as a nonsensical instruction sequence before it
; (maybe) resynchronizes at d_get.
;
;==============================================================================

asmCallOverDataTrick PROC
        call    d_get

        ; "PROTECTED" XORed with 055h, including an XORed NULL-terminator
        ; never executed --- only ever read as data via the pointer d_get \
        ; hands back
        db      005h, 007h, 01Ah, 001h, 010h, 016h, 001h, 010h, 011h, 055h

d_get:
        pop     rax              ; rax = address of the byte right after \
                                 ; `call` above, i.e. the start of our data
        ret
asmCallOverDataTrick ENDP

END


;------------------------------------------------------------------------------
; See CMakeLists.txt for build wiring
;
; x64 only: the functions above rely on the Microsoft x64 calling
; convention (first int arg in ECX, return in EAX/RAX) and use no
; instructions requiring inline asm, which x64 MSVC doesn't support ---
; this is exactly why the trick lives in its own .asm file.
;------------------------------------------------------------------------------
