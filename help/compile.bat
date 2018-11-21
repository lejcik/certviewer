@call "%CURRENT_HHCEXE%" certview.hhp

@if not "%1"=="" (@call "%1" certview.chm) else @pause
@exit /b
