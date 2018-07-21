@call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvars64.bat"


mkdir build
cd build
echo about to cmake
cmake .. -G "Visual Studio 15 2017 Win64"
