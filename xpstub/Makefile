CFLAGS = /D_CRT_SECURE_NO_WARNINGS /DUNICODE /D_WIN32_WINNT=0x0501 /D_USING_V141_SDK71_
LDFLAGS = /SUBSYSTEM:WINDOWS,"5.01" /MACHINE:X86
SYSTEM_LIBS =  kernel32.lib \
	user32.lib \
	gdi32.lib \
	winspool.lib \
	comdlg32.lib \
	advapi32.lib \
	shell32.lib \
	ole32.lib \
	oleaut32.lib \
	uuid.lib \
	odbc32.lib \
	odbccp32.lib
LIBS = fileextd.lib ntdll.lib $(SYSTEM_LIBS)

all: xpstub.dll

xpstub.dll: xpstub.obj
	@link /nologo $(LIBS) /def:xpstub.def /out:xpstub.dll $(LDFLAGS) /DLL xpstub.obj

xpstub.obj: xpstub.c
	@cl /nologo $(CFLAGS) /c xpstub.c /Foxpstub.obj

clean:
	@if exist *.obj del *.obj
	@if exist *.dll del *.dll
	@if exist *.exp del *.exp
	@if exist *.lib del *.lib