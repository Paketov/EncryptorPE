~~~~~~~~~~~~~~~~~~~~~Encryptor PE~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
!!!Written only for education purposes!!!
!!!Author not a responsibility of any use of this program.!!!

PE encryptor and PE enjector
For encrypt PE(EXE or DLL) and insert it in EXE container run: encrypt_pe.bat <dll_or_exe_for_encrypt> <result_PE_file>
 example:
	encrypt_pe.bat C:\file_to_encrypt.exe C:\encrypted_output.exe

For encrypt PE(EXE or DLL) and insert it in another PE (inject) run: enject_dll.bat <dest_dll_or_exe> <src_dll_or_exe_for_inject> <result_PE_file>
 example:
	enject_dll.bat C:\dest_exe_to_inject.exe C:\TstDll_32.dll C:\result_enjected_output.exe
	enject_dll.bat C:\dest_exe_to_inject.exe C:\exe_for_inject.exe C:\result_enjected_output.exe
	enject_dll.bat C:\dest_dll_to_inject.dll C:\TstDll_32.dll C:\result_enjected_output.dll
 warning:
	<src_dll_or_exe_for_inject> - module must continue thread(out from DllMain or WinMain)(use "/ENTRY:" linker flag) for run <dest_dll_or_exe>

For remove temp files run: clear.bat

By Solodov A. N. aka SANshine aka Paketov aka Antichrist aka CatsEater aka KittyEater aka UniverseFucker(Трахатель Вселенной) aka WorldFucker(Трахатель Мирка) - Its true, not a joke

