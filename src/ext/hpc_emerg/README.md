
# HPC Emerg
Emergency alert and tracer for realtime high-performance computing app
(work in progress, currently supported env is only Linux x86-64). 


# Example Output
```
==========================================================
  BUG: PID: 351893 at main.c:9 func_b
  Not tainted: 0; Compiler: Ubuntu Clang 11.0.1
  Signal: 4 (SIGILL); is_recoverable = 1;
  RIP: 0000000000401243 at ./main(func_b+0x33)
  Code: c7 45 f8 00 00 00 00 48 83 7d f8 64 0f 83 6e 00 00 00 e9 00 00 00 00 c6 45 f7 01 f6 45 f7 01 0f 84 43 00 00 00 e9 00 00 00 00 <0f> 0b 48 8d 05 9c 3b 00 00 e9 00 00 00 00 48 8d 05 58 3e 00 00 8a 
  RSP: 00007fff50b72e60 EFLAGS: 00010202
  RAX: 0000000000000001 RBX: 00000000004021f0 RCX: 0000000000000000
  RDX: 0000000000000000 RSI: 00000000004062a0 RDI: 0000000000000001
  RBP: 00007fff50b72e70 R08: 0000000000000000 R09: 00007fa15d37cac0
  R10: 000000000040301c R11: 0000000000000246 R12: 0000000000401120
  R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
  CS: 0033 GS: 0000 FS: 0000 SS: 002b
  CR2: 0000000000000000

  RSP Dump:
  %rsp => 0x7fff50b72e60 | 70 2e b7 50 ff 7f 00 01 00 00 00 00 00 00 00 00 |p..P............|
          0x7fff50b72e70 | 80 2e b7 50 ff 7f 00 00 a9 12 40 00 00 00 00 00 |...P......@.....|
          0x7fff50b72e80 | a0 2e b7 50 ff 7f 00 00 dc 12 40 00 00 00 00 00 |...P......@.....|
          0x7fff50b72e90 | 00 00 00 00 00 00 00 00 40 c3 37 5d 01 00 00 00 |........@.7]....|
          0x7fff50b72ea0 | c0 2e b7 50 ff 7f 00 00 d2 12 40 00 00 00 00 00 |...P......@.....|
          0x7fff50b72eb0 | 00 00 00 00 00 00 00 00 00 00 00 00 02 00 00 00 |................|
          0x7fff50b72ec0 | e0 2e b7 50 ff 7f 00 00 d2 12 40 00 00 00 00 00 |...P......@.....|
          0x7fff50b72ed0 | 00 00 00 00 00 00 00 00 00 00 00 00 03 00 00 00 |................|

  Call Trace: 
          [0x00000000401c91] ./main(??? 0+0x401c91)
          [0x000000004016d1] ./main(??? 0+0x4016d1)
          [0x000000004015cb] ./main(??? 0+0x4015cb)
          [0x00000000401526] ./main(??? 0+0x401526)
          [0x007fa15d25e040] /lib/x86_64-linux-gnu/libc.so.6(??? 0+0x5d25e040)
  %rip => [0x00000000401243] ./main(func_b+0x33)
          [0x000000004012a9] ./main(func_a+0x9)
          [0x000000004012dc] ./main(func_ss+0x2c)
          [0x000000004012d2] ./main(func_ss+0x22)
          [0x000000004012d2] ./main(func_ss+0x22)
          [0x000000004012d2] ./main(func_ss+0x22)
          [0x000000004012d2] ./main(func_ss+0x22)
          [0x0000000040133b] ./main(main+0x4b)
          [0x007fa15d245565] /lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xd5)
          [0x0000000040114e] ./main(_start+0x2e)
==========================================================
```

# Maintainer
- Ammar Faizi (<a href="https://github.com/ammarfaizi2">@ammarfaizi2</a>)


# License
This project is licensed under the GNU GPL-2.0.
