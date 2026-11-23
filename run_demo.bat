@echo off
rem One-click demo: double-click this file. Requires Python 3.11+ and git.
if not exist "%~dp0pipeline.py" (
    echo Project files not found next to run_demo.bat.
    echo Most likely the bat was run INSIDE the zip archive.
    echo Unpack the WHOLE archive first: right click - Extract All - then run from the unpacked folder.
    pause
    goto :eof
)
where py >nul 2>nul && (py "%~dp0run_demo.py" & goto :done)
where python >nul 2>nul && (python "%~dp0run_demo.py" & goto :done)
echo Python not found. Install from https://www.python.org/downloads/ and tick "Add to PATH".
pause
goto :eof
:done
echo.
echo Done. You can close this window. The report is in the demo_out folder - open report.html.
pause
