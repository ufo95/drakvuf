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


/*
setup stack for CreateProcessA call

BOOL WINAPI CreateProcess(
  _In_opt_    LPCTSTR               lpApplicationName,
  _Inout_opt_ LPTSTR                lpCommandLine,
  _In_opt_    LPSECURITY_ATTRIBUTES lpProcessAttributes,
  _In_opt_    LPSECURITY_ATTRIBUTES lpThreadAttributes,
  _In_        BOOL                  bInheritHandles,
  _In_        DWORD                 dwCreationFlags,
  _In_opt_    LPVOID                lpEnvironment,
  _In_opt_    LPCTSTR               lpCurrentDirectory,
  _In_        LPSTARTUPINFO         lpStartupInfo,
  _Out_       LPPROCESS_INFORMATION lpProcessInformation
);
*/
bool pass_inputs(struct injecthollowing *injector, drakvuf_trap_info_t *info) {

    vmi_instance_t vmi = injector->vmi;
    reg_t rsp = info->regs->rsp;
    reg_t gs = info->regs->gs_base;

    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
    };

    addr_t stack_base, stack_limit;

    // get thread stack_base
    ctx.addr = gs + injector->offsets[NT_TIB_STACKBASE];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_base))
        goto err;

    // get thread stack_limit
    ctx.addr = gs + injector->offsets[NT_TIB_STACKLIMIT];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_limit))
        goto err;

    // Push input arguments on the stack
    // CreateProcess(NULL, TARGETPROC, NULL, NULL, 0, CREATE_SUSPENDED, NULL, NULL, &si, pi))

    uint64_t nul64 = 0;
    uint8_t nul8 = 0;
    size_t len = strlen(injector->target_proc);
    addr_t str_addr, sip_addr;

    addr_t addr = rsp;

    addr -= 0x8; // the stack has to be alligned to 0x8
                 // and we need a bit of extra buffer before the string for \0

    // we just going to null out that extra space fully
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    // this string has to be aligned as well!
    addr -= len + 0x8 - (len % 0x8);
    str_addr = addr;
    ctx.addr = addr;
    if (len != vmi_write(vmi, &ctx, (void*) injector->target_proc, len))
        goto err;

    // add null termination
    ctx.addr = addr+len;
    if (VMI_FAILURE == vmi_write_8(vmi, &ctx, &nul8))
        goto err;

    struct startup_info_64 si;
    memset(&si, 0, sizeof(struct startup_info_64));
    struct process_information_64 pi;
    memset(&pi, 0, sizeof(struct process_information_64));

    // push process_information local variable on the stack
    len = sizeof(struct process_information_64);
    addr -= len;
    injector->process_info = addr;
    ctx.addr = addr;
    if (len != vmi_write(vmi, &ctx, &pi, len))
        goto err;

    // push startup_info local variable on the stack
    len = sizeof(struct startup_info_64);
    addr -= len;
    sip_addr = addr;
    ctx.addr = addr;
    if (len != vmi_write(vmi, &ctx, &si, len))
        goto err;

    //http://www.codemachine.com/presentations/GES2010.TRoy.Slides.pdf
    //
    //First 4 parameters to functions are always passed in registers
    //P1=rcx, P2=rdx, P3=r8, P4=r9
    //5th parameter onwards (if any) passed via the stack

    //p10
    // _Out_ LPPROCESS_INFORMATION lpProcessInformation
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &injector->process_info))
        goto err;

    //p9
    // _In_ LPSTARTUPINFO lpStartupInfo
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &sip_addr))
        goto err;

    //p8
    // _In_opt_ LPCTSTR lpCurrentDirectory
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    //p7
    // _In_opt_ LPVOID lpEnvironment
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    //p6
    // _In_ DWORD dwCreationFlags
    // use flag: CREATE_SUSPENDED = 0x00000004
    uint64_t flag_create_suspended = 0x4;
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &flag_create_suspended))
        goto err;

    //p5
    // _In_ BOOL bInheritHandles
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    // allocate 0x8 * 4 = 0x20 space on the stack for 4 params
    // 1th-2nd-3rd-4th params are passed in registers
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
    goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    //p1
    // _In_opt_ LPCTSTR lpApplicationName
    info->regs->rcx = 0;
    //p2
    // _Inout_opt_ LPTSTR lpCommandLine
    info->regs->rdx = str_addr;
    //p3
    // _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes
    info->regs->r8 = 0;
    //p4
    // _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes
    info->regs->r9 = 0;

    // save the return address
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &info->regs->rip))
        goto err;


    // Grow the stack
    info->regs->rsp = addr;

    return 1;

err:
    PRINT_DEBUG("Failed to pass inputs to hijacked function!\n");
    return 0;
}


// CR3 trap callback
event_response_t cr3_callback(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {

    struct injecthollowing *injector = info->trap->data;
    addr_t thread = 0;
    reg_t cr3 = info->regs->cr3;
    status_t status;

    PRINT_DEBUG("CR3 changed to 0x%" PRIx64 "\n", info->regs->cr3);

    // check trap is in the right process
    if (cr3 != injector->target_cr3)
        return 0;

    // get current thread address
    thread = drakvuf_get_current_thread(drakvuf, info->vcpu);
    if (!thread) {
        PRINT_DEBUG("cr3_cb: Failed to find current thread\n");
        return 0;
    }

    // get current thread id
    uint32_t threadid = 0;
    if ( !drakvuf_get_current_thread_id(injector->drakvuf, info->vcpu, &threadid) || !threadid )
        return 0;

    PRINT_DEBUG("Thread @ 0x%lx. ThreadID: %u\n", thread, threadid);

    // if a target tid was specified, check we are in the right thread
    if ( injector->target_tid && injector->target_tid != threadid)
        return 0;

    /*
     * At this point the process is still in kernel mode, so
     * we need to trap when it enters into user mode.
     *
     * For 64-bit Windows we use the trapframe approach, where we read
     * the saved RIP from the stack trap frame and trap it.
     * When this address is hit, we hijack the flow and afterwards return
     * the registers to the original values, thus the process continues to run.
     * This method is workable on 32-bit Windows as well but finding the trapframe
     * sometimes fail for yet unknown reasons.
     */
    addr_t trapframe = 0;
    status = vmi_read_addr_va(injector->vmi,
                    thread + injector->offsets[KTHREAD_TRAPFRAME],
                    0, &trapframe);

    if (status == VMI_FAILURE || !trapframe) {
        PRINT_DEBUG("cr3_cb: failed to read trapframe (0x%lx)\n", trapframe);
        return 0;
    }

    status = vmi_read_addr_va(injector->vmi,
                    trapframe + injector->offsets[KTRAP_FRAME_RIP],
                    0, &injector->bp.breakpoint.addr);

    if (status == VMI_FAILURE || !injector->bp.breakpoint.addr) {
        PRINT_DEBUG("Failed to read RIP from trapframe or RIP is NULL!\n");
        return 0;
    }

    injector->bp.type = BREAKPOINT;
    injector->bp.name = "entry";
    injector->bp.cb = injector_int3_cb;
    injector->bp.data = injector;
    injector->bp.breakpoint.lookup_type = LOOKUP_DTB;
    injector->bp.breakpoint.dtb = cr3;
    injector->bp.breakpoint.addr_type = ADDR_VA;

    if ( drakvuf_add_trap(drakvuf, &injector->bp) ) {
        PRINT_DEBUG("Got return address 0x%lx from trapframe and it's now trapped!\n",
                    injector->bp.breakpoint.addr);

        // Unsubscribe from the CR3 trap
        drakvuf_remove_trap(drakvuf, info->trap, NULL);
    } else
        fprintf(stderr, "Failed to trap trapframe return address\n");

    return 0;
}


// trap frame injection
event_response_t injector_int3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {

    struct injecthollowing *injector = info->trap->data;
    reg_t cr3 = info->regs->cr3;

    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = cr3,
    };

    PRINT_DEBUG("INT3 Callback @ 0x%lx. CR3 0x%lx.\n",
                info->regs->rip, cr3);

    // check trap is in the right process
    if ( cr3 != injector->target_cr3 ) {
        PRINT_DEBUG("INT3 received but CR3 (0x%lx) doesn't match target process (0x%lx)\n",
                    cr3, injector->target_cr3);
        return 0;
    }

    // get current thread id
    uint32_t threadid = 0;
    if ( !drakvuf_get_current_thread_id(injector->drakvuf, info->vcpu, &threadid) || !threadid )
        return 0;

    if ( !injector->hijacked && info->regs->rip == injector->bp.breakpoint.addr ) {
        /* We just hit the RIP from the trapframe */

        // backup registers
        memcpy(&injector->saved_regs, info->regs, sizeof(x86_registers_t));

        // setup stack for CreateProcessA call
        if ( !pass_inputs(injector, info) ) {
            PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
            return 0;
        }

        // inject process calling CreateProcessA
        info->regs->rip = injector->createprocessa;

        // set hijacked state for next trap cases
        injector->hijacked = 1;

        if ( !injector->target_tid )
            injector->target_tid = threadid;

        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }

    // trap case not interesting (wrong)
    if ( !injector->hijacked || info->regs->rip != injector->bp.breakpoint.addr || threadid != injector->target_tid )
        return 0;

    // We are now in the return path from CreateProcessA

    drakvuf_interrupt(drakvuf, -1);
    drakvuf_remove_trap(drakvuf, &injector->bp, NULL);

    // RAX contains CreateProcessA return value (!0 for success, 0 for failure)
    PRINT_DEBUG("RAX: 0x%lx\n", info->regs->rax);

    // check CreateProcessA return value
    if (! info->regs->rax) {
        PRINT_DEBUG("Error: CreateProcessA failed\n");
        injector->rc = 0;
        goto endint;
    }

    // PROCESS_INFORMATION struct receives identification information about the new process
    ctx.addr = injector->process_info;

    // read PROCESS_INFORMATION
    struct process_information_64 pip = { 0 };
    if ( sizeof(struct process_information_64) == vmi_read(injector->vmi, &ctx, &pip, sizeof(struct process_information_64)) )
    {
        injector->pid = pip.dwProcessId;
        injector->tid = pip.dwThreadId;
        injector->hProc = pip.hProcess;
        injector->hThr = pip.hThread;
    }

    if (!injector->pid || !injector->tid) {
        PRINT_DEBUG("Failed to inject\n");
        injector->rc = 0;
        goto endint;
    }
    
    PRINT_DEBUG("Injected PID: %u. TID: %u\n", injector->pid, injector->tid);
    injector->rc = info->regs->rax;


//////////////////////////////////////////////
    // get EPROCESS from pid
    addr_t eprocess_base = 0;
    if ( !drakvuf_find_process(injector->drakvuf, injector->pid, NULL, &eprocess_base) ) {
        PRINT_DEBUG("Failed to get EPROCESS from pid\n");
        injector->rc = 0;
        goto endint;
    }

    addr_t peb=0;
    if (VMI_FAILURE == vmi_read_addr_va(injector->vmi, eprocess_base + injector->offsets[EPROCESS_PEB], 0, &peb)) {
        PRINT_DEBUG("Failed to get PEB from EPROCESS\n");
        injector->rc = 0;
        goto endint;
    }

    if (VMI_FAILURE == vmi_read_addr_va(injector->vmi, eprocess_base + injector->offsets[EPROCESS_PDBASE], 0, &ctx.dtb)) {
        PRINT_DEBUG("Failed to get PDBASE from EPROCESS\n");
        injector->rc = 0;
        goto endint;
    }

/////
/*  SAMPLE...
    access_context_t ctx = {.translate_mechanism = VMI_TM_PROCESS_DTB};

    if(VMI_FAILURE == vmi_read_addr_va(vmi, eprocess_base + injector->offsets[EPROCESS_PEB], 0, &peb))
        return -1;

    if(VMI_FAILURE == vmi_read_addr_va(vmi, eprocess_base + injector->offsets[EPROCESS_PDBASE], 0, &ctx.dtb))
        return -1;

    ctx.addr = peb + injector->offsets[PEB_SESSIONID];
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &userid) )
        return -1;
*/
/////

    ctx.addr = peb + injector->offsets[PEB_IMAGEBASADDRESS];

    addr_t image_base_address = 0;
    if (VMI_FAILURE == vmi_read_addr(injector->vmi, &ctx, &image_base_address)) {
        PRINT_DEBUG("Failed to get ImageBaseAddress from PEB\n");
        injector->rc = 0;
        goto endint;
    }
    PRINT_DEBUG("ImageBaseAddress: 0x%lx\n", image_base_address);

    // read IMAGE_DOS_HEADER
    struct image_dos_header doshdr = { 0 };
    ctx.addr = image_base_address;
    if ( sizeof(struct image_dos_header) != vmi_read(injector->vmi, &ctx, &doshdr, sizeof(struct image_dos_header)) )
    {
        PRINT_DEBUG("Failed to get IMAGE_DOS_HEADER\n");
        injector->rc = 0;
        goto endint;
    }
    PRINT_DEBUG("IMAGE_DOS_HEADER->e_magic: 0x%x\n", doshdr.e_magic);

    // read IMAGE_NT_HEADERS64
    struct image_nt_headers64 imgnthdr = { 0 };
    ctx.addr = image_base_address + doshdr.e_lfanew;
    if ( sizeof(struct image_nt_headers64) != vmi_read(injector->vmi, &ctx, &imgnthdr, sizeof(struct image_nt_headers64)) )
    {
        PRINT_DEBUG("Failed to get IMAGE_NT_HEADERS64\n");
        injector->rc = 0;
        goto endint;
    }
    PRINT_DEBUG("IMAGE_NT_HEADERS64->Signature: 0x%x\n", imgnthdr.Signature);
    PRINT_DEBUG("IMAGE_NT_HEADERS64->FileHeader->NumberOfSections: 0x%x\n", imgnthdr.FileHeader.NumberOfSections);

    // read IMAGE_SECTION_HEADER
    struct image_section_header imgsecthdr = { 0 };
    ctx.addr = image_base_address + doshdr.e_lfanew + sizeof(struct image_nt_headers64);
    if ( sizeof(struct image_section_header) != vmi_read(injector->vmi, &ctx, &imgsecthdr, sizeof(struct image_section_header)) )
    {
        PRINT_DEBUG("Failed to get IMAGE_SECTION_HEADER\n");
        injector->rc = 0;
        goto endint;
    }
    PRINT_DEBUG("IMAGE_SECTION_HEADER->Name: %s\n", imgsecthdr.Name);

//////////////////////////////////////////////

endint:

    injector->hijacked = 0;

    // restore saved register so normal execution is restored
    memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));
    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}


int injecthollowing_start_app(drakvuf_t drakvuf, vmi_pid_t pid, uint32_t tid, const char *app) {

    struct injecthollowing injector = { 0 };
    injector.drakvuf = drakvuf;
    injector.vmi = drakvuf_lock_and_get_vmi(drakvuf);
    injector.rekall_profile = drakvuf_get_rekall_profile(drakvuf);
    injector.target_pid = pid;
    injector.target_tid = tid;
    injector.target_proc = app;

    // get page mode
    injector.is32bit = (vmi_get_page_mode(injector.vmi, 0) == VMI_PM_IA32E) ? 0 : 1;
    if (injector.is32bit)
    {
        PRINT_DEBUG("Do not support 32bit yet\n");
        goto done;
    }

    // get CR3 from pid
    injector.target_cr3 = vmi_pid_to_dtb(injector.vmi, pid);
    if (!injector.target_cr3)
    {
        PRINT_DEBUG("Unable to find target PID's DTB\n");
        goto done;
    }

    // Get the offsets from the Rekall profile
    unsigned int i;
    for (i = 0; i < OFFSET_MAX; i++) {
        if ( !drakvuf_get_struct_member_rva(injector.rekall_profile, offset_names[i][0], offset_names[i][1], &injector.offsets[i]))
        {
            PRINT_DEBUG("Failed to find offset for %s:%s\n", offset_names[i][0],
                        offset_names[i][1]);
        }
    }

    PRINT_DEBUG("Target PID %u with DTB 0x%lx to start '%s'\n", pid,
                injector.target_cr3, app);

    // get EPROCESS from pid
    addr_t eprocess_base = 0;
    if ( !drakvuf_find_process(injector.drakvuf, pid, NULL, &eprocess_base) ) {
        PRINT_DEBUG("Failed to get EPROCESS from pid\n");
        goto done;
    }

    // get kernel32.dll!CreateProcessA address
    injector.createprocessa = drakvuf_exportsym_to_va(injector.drakvuf, eprocess_base, "kernel32.dll", "CreateProcessA");
    if (!injector.createprocessa) {
        PRINT_DEBUG("Failed to get address of kernel32.dll!CreateProcessA\n");
        goto done;
    }

    // add CR3 event trap
    injector.cr3_event.type = REGISTER;
    injector.cr3_event.reg = CR3;
    injector.cr3_event.cb = cr3_callback;
    injector.cr3_event.data = &injector;
    if ( !drakvuf_add_trap(drakvuf, &injector.cr3_event) )
        goto done;

    // start drakvuf loop
    PRINT_DEBUG("Starting injection loop\n");
    drakvuf_loop(drakvuf);

    // remove CR3 event trap
    drakvuf_pause(drakvuf);
    drakvuf_remove_trap(drakvuf, &injector.cr3_event, NULL);

done:
    PRINT_DEBUG("Finished with injection. Ret: %i\n", injector.rc);
    drakvuf_release_vmi(drakvuf);
    return injector.rc;
}
