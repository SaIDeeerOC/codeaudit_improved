@echo off
rem Check YOUR repository: drag the repo folder onto this file, or run:
rem     check_repo.bat C:\path\to\repo
rem The run menu asks where to save the report (default: a separate folder per repo).
if "%~1"=="" (
    echo Drag your repository folder - the one containing .git - onto this file icon.
    echo Or run from a terminal:  check_repo.bat C:\path\to\repo
    pause
    goto :eof
)
if not exist "%~dp0run.py" (
    echo Project files not found next to check_repo.bat.
    echo Most likely the bat was run INSIDE the zip archive.
    echo Unpack the WHOLE archive first: right click - Extract All - then run from the unpacked folder.
    pause
    goto :eof
)
where py >nul 2>nul && (py "%~dp0run.py" "%~1" & goto :eof)
where python >nul 2>nul && (python "%~dp0run.py" "%~1" & goto :eof)
echo Python not found. Install from https://www.python.org/downloads/ and tick "Add to PATH".
pause
