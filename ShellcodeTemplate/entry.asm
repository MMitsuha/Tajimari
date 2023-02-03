.CODE ; !!!NOT USED!!!

EXTERN main : PROC
EXTERN OriginalEntryPoint : QWORD

EntryPoint PROC EXPORT
	call main
	jmp OriginalEntryPoint
EntryPoint ENDP

END