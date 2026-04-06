bits 64

fadd dword [rax]
fmul dword [rax]
fcom dword [rax]
fcomp dword [rax]
fsub dword [rax]
fsubr dword [rax]
fdiv dword [rax]
fdivr dword [rax]
fadd st0, st1
fmul st0, st2
fcom st0, st3
fcomp st0, st4
fsub st0, st5
fsubr st0, st6
fdiv st0, st7
fdivr st0, st1
fld dword [rax]
fst dword [rax]
fstp dword [rax]
fldenv [rax]
fldcw word [rax]
fstenv [rax]
fstcw word [rax]
fld st1
fxch st2
fnop
fchs
fabs
ftst
fxam
fld1
fldl2t
fldl2e
fldpi
fldlg2
fldln2
fldz
f2xm1
fyl2x
fptan
fpatan
fxtract
fprem1
fdecstp
fincstp
fprem
fyl2xp1
fsqrt
fsincos
frndint
fscale
fsin
fcos
fiadd dword [rax]
fimul dword [rax]
ficom dword [rax]
ficomp dword [rax]
fisub dword [rax]
fisubr dword [rax]
fidiv dword [rax]
fidivr dword [rax]
fcmovb st0, st1
fcmove st0, st2
fcmovbe st0, st3
fcmovu st0, st4
fucompp
fild dword [rax]
fisttp dword [rax]
fist dword [rax]
fistp dword [rax]
fld tword [rax]
fstp tword [rax]
fcmovnb st0, st1
fcmovne st0, st2
fcmovnbe st0, st3
fcmovnu st0, st4
fnclex
fninit
fucomi st0, st1
fcomi st0, st2
fadd qword [rax]
fmul qword [rax]
fcom qword [rax]
fcomp qword [rax]
fsub qword [rax]
fsubr qword [rax]
fdiv qword [rax]
fdivr qword [rax]
fadd st1, st0
fmul st2, st0
fsubr st3, st0
fsub st4, st0
fdivr st5, st0
fdiv st6, st0
fld qword [rax]
fisttp qword [rax]
fst qword [rax]
fstp qword [rax]
frstor [rax]
fsave [rax]
fstsw word [rax]
ffree st1
fst st2
fstp st3
fucom st4
fucomp st5
faddp st1, st0
fmulp st2, st0
fcompp
fsubrp st3, st0
fsubp st4, st0
fdivrp st5, st0
fdivp st6, st0
fiadd word [rax]
fimul word [rax]
ficom word [rax]
ficomp word [rax]
fisub word [rax]
fisubr word [rax]
fidiv word [rax]
fidivr word [rax]
fild word [rax]
fisttp word [rax]
fist word [rax]
fistp word [rax]
fbld tword [rax]
fild qword [rax]
fbstp tword [rax]
fistp qword [rax]
fnstsw ax
fucomip st0, st1
fcomip st0, st2