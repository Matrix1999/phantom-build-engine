    .section .rodata
    .global _scripts_blob_start
    .hidden _scripts_blob_start
    .global _scripts_blob_end
    .hidden _scripts_blob_end
    .balign 4
_scripts_blob_start:
    .incbin "scripts.blob"
_scripts_blob_end:
    .byte 0
