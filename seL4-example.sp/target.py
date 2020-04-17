# * Copyright 2015, NICTA
# *
# * This software may be distributed and modified according to the terms of
# * the BSD 2-Clause license. Note that NO WARRANTY is provided.
# * See "LICENSE_BSD2.txt" for details.
# *
# * @TAG(NICTA_BSD)

from target_objects import target_dir, structs, functions
from target_objects import symbols, sections, rodata, pairings
import target_objects

import syntax
import pseudo_compile
import objdump
import logic
import re

syntax.set_arch('rv64')
f = open ('%s/kernel.elf.symtab' % target_dir)
objdump.install_syms (f)
f.close ()

f = open ('%s/CFunctions.txt' % target_dir)
syntax.parse_and_install_all (f, 'C')
f.close ()

f = open ('%s/ASMFunctions_checked.txt' % target_dir)
#f = open('%s/ASMFunctions.txt' % target_dir)
(astructs, afunctions, aconst_globals) = syntax.parse_and_install_all (f, 'ASM',skip_functions= ['fastpath_call', 'fastpath_reply_recv','c_handle_syscall'])
f.close ()
assert not astructs
assert not aconst_globals

#print afunctions

#assert logic.aligned_address_sanity (afunctions, symbols, 2)

f = open ('%s/kernel.elf.rodata' % target_dir)

objdump.install_rodata (f,
        [
#            ('Section', '.rodata'),
            #('Symbol', 'kernel_devices'),
#	    ('Symbol', 'avail_p_regs'),
            #('Symbol', 'dev_p_regs')
        ]
)

f.close ()


print 'Pseudo-Compiling.'
pseudo_compile.compile_funcs (functions)

print 'Doing stack/inst logic.'

def make_pairings ():
	pairs = [(s, 'Kernel_C.' + s) for s in functions
		if ('Kernel_C.' + s) in functions]
	target_objects.use_hooks.add ('stack_logic')
	target_objects.use_hooks.add('assume_sp_equal')
	import stack_logic
	stack_bounds = '%s/StackBounds.txt' % target_dir
	new_pairings = stack_logic.mk_stack_pairings (pairs, stack_bounds, False)
	pairings.update (new_pairings)

make_pairings ()

import inst_logic
inst_logic.add_inst_specs ()

print 'Checking.'
syntax.check_funs (functions)

