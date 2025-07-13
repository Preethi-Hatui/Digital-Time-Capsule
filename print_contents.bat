@echo off
cd /d %~dp0

echo.
echo === Project Directory: %cd% ===
echo ---------------------------------------

rem Recursively print content of all files
for /r %%f in (*) do (
    echo.
    echo ============================
    echo File: %%f
    echo ============================
    type "%%f"
)

echo.
echo -------- End of Files --------
pause
