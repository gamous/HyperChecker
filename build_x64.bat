@call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
ml64 /Fo HvChk_asm_64.obj /c HvChk_x64.asm
cl HvChk.cpp HvChk_asm_64.obj /FeHvChk_x64.exe -std:c++14 /EHsc
del *.obj