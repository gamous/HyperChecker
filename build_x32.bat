@call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars32.bat"
ml /Fo HvChk_asm_32.obj /c HvChk_x32.asm
cl HvChk.cpp HvChk_asm_32.obj  /FeHvChk_x32.exe -std:c++14 /EHsc
del *.obj