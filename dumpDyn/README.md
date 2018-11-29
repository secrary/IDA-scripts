# dumpDyn

Let's say, a process allocates a dynamic memory and maps a shellcode or a code section of an executable into the memory. If we comment, set breakpoints, set function names, etc. In the next execution, there will be nothing, due to the shellcode / the code section will take different memory address.

`dumpDyn.py` is `IDAPython` script which saves `comments`, `names` and `breakpoints` from one execution to another.

## [DEMO: https://youtu.be/qQRu2PP_q5c](https://youtu.be/qQRu2PP_q5c)