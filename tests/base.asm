bits 64

add [rax], al
add [rax], eax
add al, [rax]
add eax, [rax]
add al, 0x10
add eax, 0x10000
or [rax], al
or [rax], eax
or al, [rax]
or eax, [rax]
or al, 0x10
or eax, 0x10000
adc [rax], al
adc [rax], eax
adc al, [rax]
adc eax, [rax]
adc al, 0x10
adc eax, 0x10000
sbb [rax], al
sbb [rax], eax
sbb al, [rax]
sbb eax, [rax]
sbb al, 0x10
sbb eax, 0x10000
and [rax], al
and [rax], eax
and al, [rax]
and eax, [rax]
and al, 0x10
and eax, 0x10000
sub [rax], al
sub [rax], eax
sub al, [rax]
sub eax, [rax]
sub al, 0x10
sub eax, 0x10000
xor [rax], al
xor [rax], eax
xor al, [rax]
xor eax, [rax]
xor al, 0x10
xor eax, 0x10000
cmp [rax], al
cmp [rax], eax
cmp al, [rax]
cmp eax, [rax]
cmp al, 0x10
cmp eax, 0x10000
push rax
push rcx
push rdx
push rbx
push rsp
push rbp
push rsi
push rdi
pop rax
pop rcx
pop rdx
pop rbx
pop rsp
pop rbp
pop rsi
pop rdi
movsxd rax, [rax]
imul eax, [rax], 0x1000
push byte 0x10
imul eax, [rax], byte 0x10
insb
insd
outsb
outsd
jo short $+2
jno short $+2
jb short $+2
jnb short $+2
je short $+2
jne short $+2
jbe short $+2
ja short $+2
js short $+2
jns short $+2
jp short $+2
jnp short $+2
jl short $+2
jge short $+2
jle short $+2
jg short $+2
add byte [rax], 0x10
add dword [rax], 0x10000
add dword [rax], byte 0x10
test [rax], al
test [rax], eax
xchg [rax], al
xchg [rax], eax
mov [rax], al
mov [rax], eax
mov al, [rax]
mov eax, [rax]
mov [rax], es
lea eax, [rax+rcx]
mov es, [rax]
pop qword [rax]
nop
xchg eax, ecx
xchg eax, edx
xchg eax, ebx
xchg eax, esp
xchg eax, ebp
xchg eax, esi
xchg eax, edi
cwde
cdq
fwait
pushfq
popfq
sahf
lahf
mov al, [abs 0x1000]
mov eax, [abs 0x1000]
mov [abs 0x1000], al
mov [abs 0x1000], eax
movsb
movsd
cmpsb
cmpsd
test al, 0x10
test eax, 0x10000
stosb
stosd
lodsb
lodsd
scasb
scasd
mov al, 0x10
mov cl, 0x10
mov dl, 0x10
mov bl, 0x10
mov ah, 0x10
mov ch, 0x10
mov dh, 0x10
mov bh, 0x10
mov eax, 0x10000
mov ecx, 0x10000
mov edx, 0x10000
mov ebx, 0x10000
mov esp, 0x10000
mov ebp, 0x10000
mov esi, 0x10000
mov edi, 0x10000
ror byte [rax], 0x02
ror dword [rax], 0x02
ret 0x10
ret
enter 0x100, 0x00
leave
retf 0x10
retf
int3
int 0x80
iretq
rol byte [rax], 1
rol dword [rax], 1
rol byte [rax], cl
rol dword [rax], cl
xlat
loopne $+2
loope $+2
loop $+2
jecxz $+2
in al, 0x60
in eax, 0x60
out 0x60, eax
call $+5
jmp $+5
jmp short $+2
in al, dx
in eax, dx
out dx, al
out dx, eax
hlt
cmc
test byte [rax], 0x10
test dword [rax], 0x10000
clc
stc
cli
sti
cld
std
inc byte [rax]
inc dword [rax]
push fs
pop fs
cpuid
bt [rax], eax
shld [rax], eax, cl
push gs
pop gs
rsm
bts [rax], eax
shrd [rax], eax, 0x04
shld [rax], eax, 0x04
shrd [rax], eax, cl
imul eax, [rax]
cmpxchg [rax], al
cmpxchg [rax], eax
btr [rax], eax
movzx eax, byte [rax]
movzx eax, word [rax]
popcnt eax, [rax]
bt [rax], byte 0x04
btc [rax], eax
bsf eax, [rax]
bsr eax, [rax]
movsx eax, byte [rax]
movsx eax, word [rax]
xadd [rax], al
xadd [rax], eax
bswap eax
bswap ecx
bswap edx
bswap ebx
bswap esp
bswap ebp
bswap esi
bswap edi
syscall
clts
sysret
invd
wbinvd
ud2
nop dword [rax]
wrmsr
rdtsc
rdmsr
rdpmc
sysenter
sysexit
cmovo eax, [rax]
cmovno eax, [rax]
cmovb eax, [rax]
cmovnb eax, [rax]
cmove eax, [rax]
cmovne eax, [rax]
cmovbe eax, [rax]
cmova eax, [rax]
cmovs eax, [rax]
cmovns eax, [rax]
cmovp eax, [rax]
cmovnp eax, [rax]
cmovl eax, [rax]
cmovge eax, [rax]
cmovle eax, [rax]
cmovg eax, [rax]
jo near $+6
jno near $+6
jb near $+6
jnb near $+6
je near $+6
jne near $+6
jbe near $+6
ja near $+6
js near $+6
jns near $+6
jp near $+6
jnp near $+6
jl near $+6
jge near $+6
jle near $+6
jg near $+6
seto byte [rax]
setno byte [rax]
setb byte [rax]
setnb byte [rax]
sete byte [rax]
setne byte [rax]
setbe byte [rax]
seta byte [rax]
sets byte [rax]
setns byte [rax]
setp byte [rax]
setnp byte [rax]
setl byte [rax]
setge byte [rax]
setle byte [rax]
setg byte [rax]
rep movsb
rep movsd
rep stosb
rep stosd
rep lodsb
rep lodsd
repne cmpsb
repne cmpsd
repne scasb
repne scasd