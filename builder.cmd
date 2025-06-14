@ECHO OFF

SET FILE_NAME=dw

PyInstaller --clean %FILE_NAME%.spec

COPY /Y dist\%FILE_NAME%.exe

RMDIR /S /Q __pycache__
RMDIR /S /Q build
RMDIR /S /Q dist

PAUSE