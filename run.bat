@echo off
rem Main menu of CodeAudit: double-click this file.
rem You can also DRAG a repository folder onto this file icon - it will be checked immediately.
if not exist "%~dp0run.py" (
    echo Project files not found next to run.bat.
    echo Most likely the bat was run INSIDE the zip archive.
    echo Unpack the WHOLE archive first: right click - Extract All - then run from the unpacked folder.
    pause
    goto :eof
)
where py >nul 2>nul && (py "%~dp0run.py" %~1 & goto :eof)
where python >nul 2>nul && (python "%~dp0run.py" %~1 & goto :eof)
echo Python not found. Install from https://www.python.org/downloads/ and tick "Add to PATH".
pause
