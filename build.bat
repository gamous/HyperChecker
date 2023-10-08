@call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
ml64 /Fo HvChk_asm.obj /c HvChk.asm
cl HvChk.cpp HvChk_asm.obj  /FeHvChk.exe -std:c++14 /EHsc
del *.obj