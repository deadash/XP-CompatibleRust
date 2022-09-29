## 目标

读取目标EXE/DLL后，通过导入的库文件和函数，不支持xp的函数全部修改重定位到 xpstub.dll 里面

## 核心模块

通过xp兼容的lib来判断函数是否支持, 例如路径`C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Lib`

通过 `dumpbin` 生成函数列表，例如 `dumpbin /EXPORTS [TARGETLIB] > [TARGET.TXT]`

### kernel32

存在比较多的函数变动

