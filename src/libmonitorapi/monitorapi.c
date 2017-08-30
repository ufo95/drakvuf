 /*********************IMPORTANT DRAKVUF LICENSE TERMS**********************
 *                                                                         *
 * DRAKVUF (C) 2014-2017 Tamas K Lengyel.                                  *
 * Tamas K Lengyel is hereinafter referred to as the author.               *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed DRAKVUF technology into proprietary   *
 * software, alternative licenses can be aquired from the author.          *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files.                             *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * DRAKVUF with other software in compressed or archival form does not     *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * DRAKVUF or grant special permissions to use it in other open source     *
 * software.  Please contact tamas.k.lengyel@gmail.com with any such       *
 * requests.  Similarly, we don't incorporate incompatible open source     *
 * software into Covered Software without special permission from the      *
 * copyright holders.                                                      *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * DRAKVUF in other works, are happy to help.  As mentioned above,         *
 * alternative license can be requested from the author to integrate       *
 * DRAKVUF into proprietary applications and appliances.  Please email     *
 * tamas.k.lengyel@gmail.com for further information.                      *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port DRAKVUF to new platforms, fix bugs, *
 * and add new features.  You are highly encouraged to submit your changes *
 * on https://github.com/tklengyel/drakvuf, or by other methods.           *
 * By sending these changes, it is understood (unless you specify          *
 * otherwise) that you are offering unlimited, non-exclusive right to      *
 * reuse, modify, and relicense the code.  DRAKVUF will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).                                        *
 * To specify special license conditions of your contributions, just say   *
 * so when you send them.                                                  *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the DRAKVUF   *
 * license file for more details (it's in a COPYING file included with     *
 * DRAKVUF, and also available from                                        *
 * https://github.com/tklengyel/drakvuf/COPYING)                           *
 *                                                                         *
 ***************************************************************************/

// example:
// sudo ./monitorapi /home/simone/vm/win10/windows10prox64.ea5870420d85492eac11a1a56c7a27a21.rekall.json windows10prox64 NtDeviceIoControlFile /home/simone/vm/win10/ea5870420d85492eac11a1a56c7a27a21/dlls/ntdll.json


#include <libvmi/libvmi.h>
#include <libvmi/libvmi_extra.h>
#include <libvmi/x86.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <signal.h>
#include <inttypes.h>
#include <glib.h>

#include "libdrakvuf/libdrakvuf.h"
#include "private.h"


struct monitorapi {
    // Inputs:
    const char *apifunction;            //OK
    const char *apifunction_profile;    //OK

    // Internal:
    drakvuf_t drakvuf;              //OK
    vmi_instance_t vmi;             //OK
    const char *rekall_profile;     //OK

    // Results:
    int rc;
};



static unicode_string_t* read_unicode(vmi_instance_t vmi, access_context_t *ctx)
{
    unicode_string_t *us = vmi_read_unicode_str(vmi, ctx);
    if ( !us ) {
        printf("Error vmi_read_unicode_str()\n");
        return NULL;
    }

    unicode_string_t *out = (unicode_string_t*)g_malloc0(sizeof(unicode_string_t));
    if ( !out ) {
        printf("Error g_malloc0()\n");
        vmi_free_unicode_str(us);
        return NULL;
    }

    status_t rc = vmi_convert_str_encoding(us, out, "UTF-8");
    vmi_free_unicode_str(us);

    if(VMI_SUCCESS == rc) {
        printf("read_unicode succeded: --> %s\n", out->contents);
        return out;
    }

    printf("Error vmi_convert_str_encoding()\n");
    g_free(out);
    return NULL;
}

static unicode_string_t* get_filename_from_handle(drakvuf_t drakvuf,
                                                  drakvuf_trap_info_t *info,
                                                  vmi_instance_t vmi,
                                                  access_context_t *ctx,
                                                  const char* rekall_profile,
                                                  addr_t handle)
{
    addr_t process=drakvuf_get_current_process(drakvuf, info->vcpu);
    if (!process) {
        printf("Error drakvuf_get_current_process()\n");
        return NULL;
    }

    addr_t obj = drakvuf_get_obj_by_handle(drakvuf, process, handle);
    if ( !obj ) {
        printf("Error drakvuf_get_obj_by_handle()\n");
        return NULL;
    }

    addr_t file_object_filename, object_header_body;
    if ( !drakvuf_get_struct_member_rva(rekall_profile, "_OBJECT_HEADER", "Body", &object_header_body) ) {
        printf("Error drakvuf_get_struct_member_rva #1()\n");
        return NULL;
    }
    if ( !drakvuf_get_struct_member_rva(rekall_profile, "_FILE_OBJECT", "FileName", &file_object_filename) ) {
        printf("Error drakvuf_get_struct_member_rva #2()\n");
        return NULL;
    }

    ctx->addr = obj + object_header_body + file_object_filename;
    return read_unicode(vmi, ctx);
}


/*OK*/
/* Function:

NTSTATUS WINAPI NtDeviceIoControlFile(
  _In_  HANDLE           FileHandle,
  _In_  HANDLE           Event,
  _In_  PIO_APC_ROUTINE  ApcRoutine,
  _In_  PVOID            ApcContext,
  _Out_ PIO_STATUS_BLOCK IoStatusBlock,
  _In_  ULONG            IoControlCode,
  _In_  PVOID            InputBuffer,
  _In_  ULONG            InputBufferLength,
  _Out_ PVOID            OutputBuffer,
  _In_  ULONG            OutputBufferLength
);

*/
static event_response_t apifunction_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
    struct monitorapi *mapi = (struct monitorapi *)info->trap->data;

    printf("apifunction_cb -> vcpu=%d  CR3=0x%lx  proc=%s  module=%s  trapname=%s\n",
           info->vcpu, info->regs->cr3, info->procname, info->trap->breakpoint.module, info->trap->name);
    printf("RCX=0x%lx  RDX=0x%lx  R8=0x%lx  R9=0x%lx\n", info->regs->rcx, info->regs->rdx, info->regs->r8, info->regs->r9);


    vmi_instance_t vmi = mapi->vmi;

    size_t sp_size = 8 * 12;
    unsigned char* buf = NULL;
    buf = (unsigned char *)g_malloc(sizeof(char) * sp_size);
    uint32_t *buf32 = (uint32_t *)buf;
    uint64_t *buf64 = (uint64_t *)buf;

    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;
    ctx.addr = info->regs->rsp;

    if ( sp_size != vmi_read(vmi, &ctx, &(buf64[0]), sp_size) ) {
        printf("Error reading args\n");
        goto exit;
    }

    for (int i=0; i<12; i++) {
        printf("ESP+0x%x @0x%lx  [ 0x%lx ]\n", i*8, info->regs->rsp+(i*8), buf64[i]);
    }
exit:
    g_free(buf);
    return 0;
}

/*
static event_response_t apifunction_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
    struct monitorapi *mapi = (struct monitorapi *)info->trap->data; 
    printf("\n---> apifunction_cb <---\n");

    unsigned int i = 0;
    uint8_t reg_size = 8;       // 64bit register
    unsigned int nargs = 10;    // NtDeviceIoControlFile() #args
    size_t size = 0;
    unsigned char* buf = NULL;  // pointer to buffer to hold argument values

    size = reg_size * nargs;     // stack args size
    buf = (unsigned char *)g_malloc(sizeof(char)*size);

    uint32_t *buf32 = (uint32_t *)buf;
    uint64_t *buf64 = (uint64_t *)buf;

//    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    vmi_instance_t vmi = mapi->vmi;

    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    // First 4 args on registers
    buf64[0] = info->regs->rcx;
    buf64[1] = info->regs->rdx;
    buf64[2] = info->regs->r8;
    buf64[3] = info->regs->r9;

    // first 4 agrs passed via rcx, rdx, r8, and r9
    ctx.addr = info->regs->rsp+0x28;  // jump over homing space + base pointer
    size_t sp_size = reg_size * (nargs-4);
    if ( sp_size != vmi_read(vmi, &ctx, &(buf64[4]), sp_size) ) {
        printf("Error reading args\n");
        goto exit;
    }

    printf("apifunction_cb -> vcpu=%d  CR3=0x%lx  proc=%s  module=%s  trapname=%s\n",
           info->vcpu, info->regs->cr3, info->procname, info->trap->breakpoint.module, info->trap->name);

    addr_t val = 0;

    // ====> arg #0
    //   _In_  HANDLE           FileHandle,
    val = buf64[0];
    printf("#0: @ 0x%lx -> _In_  HANDLE -> ", val);    
    unicode_string_t *us = get_filename_from_handle(drakvuf, info, vmi, &ctx, mapi->rekall_profile, val);
    if ( us ) {
        printf("%s", us->contents);
        vmi_free_unicode_str(us);
    }
    printf("\n");

    // ====> arg #5
    //  _In_  ULONG            IoControlCode,
    val = buf64[5];

    ctx.addr = val;
    printf("#5: @ 0x%lx -> _In_  ULONG -> ", val);
    uint32_t arg5 = 0;
    if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, &arg5) )
        goto exit;
    printf("0x%x\n", arg5);    


exit:
    g_free(buf);
//    drakvuf_release_vmi(drakvuf);
    return 0;
}
*/

/*OK*/
int monitorapi_start(drakvuf_t drakvuf, const char *apifunction, const char *apifunction_profile) {
    struct monitorapi mapi = { 0 };
    mapi.drakvuf = drakvuf;
    mapi.vmi = drakvuf_lock_and_get_vmi(drakvuf);
    mapi.rekall_profile = drakvuf_get_rekall_profile(drakvuf);
    mapi.apifunction = apifunction;
    mapi.apifunction_profile = apifunction_profile;

    // 64bit support only, at the moment
    if (vmi_get_page_mode(mapi.vmi, 0) != VMI_PM_IA32E) {
        printf("32bit OS not supported\n");
        goto done;        
    }

    drakvuf_trap_t *api_trap = (drakvuf_trap_t *)g_malloc0(sizeof(drakvuf_trap_t));
    api_trap->breakpoint.lookup_type = LOOKUP_PID;
    api_trap->breakpoint.pid = 3888;
//    api_trap->breakpoint.lookup_type = LOOKUP_NAME;
//    api_trap->breakpoint.proc = "explorer.exe";
    api_trap->breakpoint.addr_type = ADDR_RVA;
    api_trap->breakpoint.module = "ntdll.dll";
    api_trap->type = BREAKPOINT;
    api_trap->cb = apifunction_cb;
    api_trap->data = &mapi;

    if ( !drakvuf_get_function_rva(mapi.apifunction_profile, mapi.apifunction, &api_trap->breakpoint.rva) ) {
        printf("API Function %s not found in its rekall profile\n", mapi.apifunction);
        goto done;
    }

    if ( !drakvuf_add_trap(drakvuf, api_trap) ) {
        printf("Error in drakvuf_add_trap()\n");
        goto done;
    }


    printf("Starting injection loop\n");
    drakvuf_loop(drakvuf);


    drakvuf_pause(drakvuf);
    drakvuf_remove_trap(drakvuf, api_trap, NULL);

done:
    printf("Finished with injection. Ret: %i\n", mapi.rc);
    drakvuf_release_vmi(drakvuf);
    return mapi.rc;
}
