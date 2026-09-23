mkdir C:\Root
mkdir C:\Root\Admin
mkdir C:\Root\Flag
mkdir C:\Root\Cryptsaria
mkdir C:\Root\Hydroxy
mkdir C:\Root\Kaligula
mkdir C:\Root\Kevin
mkdir C:\Root\Mistral

reg import C:\solis_default.reg

C:\ncat.exe -l 9000 -k -v -e C:\Solis.exe
