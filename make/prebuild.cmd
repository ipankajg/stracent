echo Launch directory: "%~dp0"
pushd "..\extrn\ihulib"
echo Current directory: "%CD%"
powershell.exe -ExecutionPolicy Bypass -File ../../make/dldep.ps1
pause