StraceNT
--------
This program is a Linux strace clone for Windows. It uses IAT patching and
provides an efficient way to monitor API calls made by various DLLs.


Compile
-------
- Use Visual Studio 2013 to compile the software.
- First download IHULIB library from:
  https://github.com/IntellectualHeaven/ihulib/releases/download/v1.0/ihulib_v_1_0.zip
- Extract this to stracent/extrn/ihulib (preserve folder paths)
- You should have files like ihulib/bin/x64/Debug/ihulib.lib etc.
- Open stracent.sln in make folder and build.


Install
-------
- Download the zip file from github release tab and extract it to any folder.
- There is no special installation required. You can run stracent or straceui
  from the extracted location.


Notes
-----
Please read info.txt for more details about this program, usage and
limitations etc.

