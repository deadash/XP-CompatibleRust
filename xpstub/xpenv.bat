@REM 查找自带地vs环境
call vsenv.bat -arch=x86 -no_logo -vcvars_ver=14.16
@REM 加载 vs2017(v141_xp)环境
set PATH=C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Bin;%PATH%
set INCLUDE=C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Include;%INCLUDE%
set LIB=C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Lib;%LIB%
@REM 使用xp专用 宏
set CL=/D_USING_V110_SDK71_