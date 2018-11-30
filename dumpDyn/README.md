# dumpDyn

If a process allocates a dynamic memory using `VirtualAlloc`, `HeapAlloc`, `new`, etc. and continues execution from the address, the most of times, the memory address will be different for each different execution, it means that if we comment, rename variables or set breakpoints, nothing of this will be left in the next execution because the shellcode or code section will take a different memory address.

`dumpDyn.py` is `IDAPython` plugin(script) which saves `comments`, `names` and `breakpoints` from one execution to another.

## USAGE

![USAGE](https://user-images.githubusercontent.com/16405698/49311939-70f5b980-f4da-11e8-81d6-09bd083d4e49.PNG)

If `VirtualAlloc`/`VirtualAllocEx` is used to allocate a dynamic memory (which is in case of the most malware), you can use icons on the toolbar to `save` and `restore` your work:

[DEMO: https://www.youtube.com/watch?v=Z53AlWPAwCc](https://www.youtube.com/watch?v=Z53AlWPAwCc)

![dumpdyn_1](https://user-images.githubusercontent.com/16405698/49311767-f7f66200-f4d9-11e8-81c5-8f8c648c0c9e.gif)

In any other case(`HeapAlloc`, `malloc`, `new`, etc), you need to specify memory location and size:

![1](https://user-images.githubusercontent.com/16405698/49311821-26743d00-f4da-11e8-883a-7205df03125e.PNG)

![2](https://user-images.githubusercontent.com/16405698/49311822-270cd380-f4da-11e8-95e3-256634ff69be.PNG)

![3](https://user-images.githubusercontent.com/16405698/49311823-270cd380-f4da-11e8-8e93-e99276de14e0.gif)