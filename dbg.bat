@echo off
echo PATH IN CMD:
echo %PATH%
echo ---
where docker 2>&1
echo ---
"C:\Program Files\Docker\Docker\resources\bin\docker.exe" --version 2>&1
