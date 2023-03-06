gdb:
	gdbgui ../linux-5.15/vmlinux --host=0.0.0.0
mc: #machinecode
	python3 make_machinecode.py test.s