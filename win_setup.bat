set CYGWIN_BIN=C:\cygwin64\bin
set QT5_BASE_DIR=C:\Qt\Qt5.3.1\5.3\msvc2013_64
set QT5_BIN=C:\Qt\Qt5.3.1\5.3\msvc2013_64\bin
set MSVC_BIN="C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Bin"
set PATH=%PATH%;%CYGWIN_BIN%;%QT5_BIN%
set WIRESHARK_TARGET_PLATFORM=win64
set INCLUDE=%INCLUDE%;c:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Include
call "c:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\vcvarsall.bat" x86_amd64

