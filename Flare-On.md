# TLDR;

I fumbled my way through the UPX unpacking, and used Ghidras emulation capabilities to grab the flag.

### Initial overview

After extracting the 7z, I get a file: `garbage.exe` Upon initial inspection, I see that the file seems to be truncated at the end.

![image](https://github.com/khanhhao1363/picoCTF-writeup/assets/85216311/931042b3-b7fe-4702-b046-a64947420621)

![image](https://github.com/khanhhao1363/picoCTF-writeup/assets/85216311/f7971cd5-9e8d-4208-8a9e-414bdd721da6)

It also seemed obvious that the file was UPX packed. So my first attempt was to download the latest version of UPX and tried to unpack it. This unfortunately failed because it didn't determine the file was a valid PE file.

I've never dealt with corrupt PE files, but the manifest section looked like simple XML, so I tried copy/pasting from another binary. In addition to this, the `.rsrc` section defined in the PE header states.
```C
.rsrc section started  {0x419000-0x41a000}
```
but my truncated file was only valid to `0x419123`, so I added a bunch of nulls at the end of the file.

# Unpacked UPX

Once I fixed the XML in what I presume is the manifest section, together with the length, the exe still wouldn't run. But UPX was able to unpack it!!

So now we are able to see something in ghidra, and it was easy to find the function that looked like it was decoding two strings.
```ASM
string_1 = (undefined4 *)
                          
             "nPTnaGLkIqdcQwvieFQKGcTGOTbfMjDNmvibfBDdFBhoPaBbtfQuuGWYomtqTFqvBSKdUMmciqKSGZaosWCSoZlcIlyQpOwkcAgw "
  ;
  cp_string_1 = local_12c;
  while (iVar2 != 0) {
    iVar2 = iVar2 + -1;
    *cp_string_1 = *string_1;
    string_1 = string_1 + 1;
    cp_string_1 = cp_string_1 + 1;
  }
  iVar2 = 0x19;
  local_54 = 0x40a1e0a;
  *(undefined2 *)cp_string_1 = *(undefined2 *)string_1;
  local_50 = 0x1a021623;
  local_4c = 0x24086644;
  string_1 = (undefined4 *)
                          
             "KglPFOsQDxBPXmclOpmsdLDEPMRWbMDzwhDGOyqAkVMRvnBeIkpZIhFznwVylfjrkqprBPAdPuaiVoVugQAlyOQQtxBNsTdPZgDH "
  ;
  cp_string_1 = local_c4;
```
That seems possible....

However when trying to run the unpacked binary there are still errors, after many attempts and reading up on PE files etc, it seemed that this was due to the import tables still being corrupted.

I read several guides on how to rebuild the Import Table Directory/Import Address Table etc. Ultimately I failed, I got frustrated with not being able to fix IAT with tools like Scylla. I probably was just doing it wrong.

#### So what are the next Options???

* Static analysis of the code, reimplement it in C or python...
* Using Emulation!


# Emulation

### Using Ghidra emulation!
I found this excellent article : https://medium.com/@cetfor/emulating-ghidras-pcode-why-how-dd736d22dfb

This was also helpful : https://github.com/cetfor/GhidraSnippets

I started out with the sample code in the article, and expected to run into a ton of errors.
The first error I encountered was that the registers used were incorrect, So that was an easy fix just switching out 64bit to 32bit. EX : (RAX->EAX)
Then defined the function as the starting point (EIP) and kept the ESP and EBP the same as the examples.
```ASM
  myEntry = getSymbolAddress("FUN_0040106b")
    
    # Set initial EIP
    mainFunctionEntryLong = int("0x{}".format(myEntry), 16)
    emuHelper.writeRegister(emuHelper.getPCRegister(), mainFunctionEntryLong)
```
The next time that I ran the script it actually ran, and did a bunch of stuff. But crashed at this line :
```ASM
00401166 ff 15 0c        CALL       dword ptr [PTR_0040d00c]              -> 00012418
                 d0 40 00
```
Because `00012418` is not valid memory! Obviously because the pointer never got initialized properly. When we look at that PTR :
```ASM
0  CreateFileA  <<not bound>>
                             PTR_0040d00c                                  XREF[1]:     FUN_0040106b:00401166  
        0040d00c 18 24 01 00     addr       00012418                                    IMAGE_THUNK_DATA32
```
We can see that it's trying to call CreateFileA,  so it seemed obvious enough that it was trying to create a file. Since I don't actually want to do this, I needed to figure out how to skip over this instruction. I did so by doing :
```ASM
        if executionAddress == getAddress(0x0401166):
               emuHelper.writeRegister(emuHelper.getPCRegister(), 0x40116c)
               print("skipping")
```
I don't know if this is the best approach. It should be noted that we want this function to return a non-negative one. So eax (which is stored into `iVar2`) is already in a good state for this.
```ASM
      if (iVar2 != -1) {
    local_140 = 0;
    FUN_00401000(local_13c,(int)&local_5c,0x3d,(int)local_12c);
    (*(code *)(undefined *)0x123f8)(iVar2,local_13c[0],0x3d,&local_140,0);
    FUN_00401045(local_13c);
    (*(code *)(undefined *)0x12426)(iVar2);
    FUN_00401000(local_13c,(int)&local_1c,0x14,(int)local_c4);
    (*(code *)(undefined *)0x12442)(0,0,local_13c[0],0,0,0);
    FUN_00401045(local_13c);
  }
```
On the next run, the script failed here :
```ASM
    004011ae ff 15 04        CALL       dword ptr [PTR_0040d004]                -> 000123f8
                 d0 40 00
```
Again, it's a library call to `WriteFile`.
Since this is x86, parameters are passed to the function by pushing onto the stack :
```ASM
        004011a4 50              PUSH       EAX
        004011a5 6a 3d           PUSH       0x3d
        004011a7 ff b5 c8        PUSH       dword ptr [EBP + local_13c]
                 fe ff ff
        004011ad 56              PUSH       ESI
```
BOOM, the flag appeared :
```ASM
.
.
.
Address: 0x004011ad (PUSH ESI)
  EIP = 0x00000000004011ad
  EAX = 0x000000002ffefec0
  EBX = 0x0000000000000000
  ECX = 0x000000002ffeffa4
  EDX = 0x000000000000003c
  ESI = 0x000000002ffefec4
  EDI = 0x000000002ffeffa2
  ESP = 0x000000002ffefe88
  EBP = 0x000000002ffefffc
  eflags = 0x0000000000000000
MsgBox("Congrats! Your key is: CorruptG4rbage@flare-on.com")
2_garbage.py> Finished!
```












