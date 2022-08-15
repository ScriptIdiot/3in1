# 3in1

# WHAT IS IT:
#### 3in1 is a project aimed to Bypass Some Av Products, Using Different, Advanced Features.

# HOW DOES IT WORK:
* This repo represent some pocs i published earlier, [KCTHijack](https://gitlab.com/ORCA666/kcthijack) && [T.D.P](https://gitlab.com/ORCA666/t.d.p) and more spice using [ThreadStackSpoofer](https://github.com/mgeeky/ThreadStackSpoofer)
* We first use [KCTHijack](https://gitlab.com/ORCA666/kcthijack) to run our shellcode, in the local process
* Then we run [T.D.P](https://gitlab.com/ORCA666/t.d.p) && [ThreadStackSpoofer](https://github.com/mgeeky/ThreadStackSpoofer) to help us more in evading memory scanners while the connection is active
* 3in1 provides `xor encryption` for the shellcode to evade static analysis
* This repo also use a costum way to write, using `FillMemory` api which will write 1 byte at a time, after decrypting it, and thus we are not decrypting the shellcode at once.

# REQUIREMENTS: 
* python3 to run the encoder (which will be also used to build your exe)
* visual studio 2019 (i tested it on `v2019`)
* msbuild.exe which will be used to build the project and comes with visual studio

# USAGE:
* first of all generate your shellcode as raw format (bin), for memory evasion please use something like cobalt strike to make [T.D.P](https://gitlab.com/ORCA666/t.d.p) work ...
* open `Developer Command Prompt for your vs version`
* navigate to 3in1 project, by typing `cd <path to the repo>` 
* then use python3 to run the python script as so : `python encoder.py <your file name .bin>`
* if everything worked fine you will see the `3in1.exe` file in `\x64\Release\` directory
* of coures you can update the [key](https://gitlab.com/ORCA666/3in1/-/blob/main/encoder.py#L5) in `encoder.py` .

# NOTE: The project only work on `x64` systems

# AT THE END:
#### all the techs that are used here are already discussed in earlier repos, however in case of any problems, please report it as issue and i will be at your service ...

<h6 align="center"> <i>#                                   STAY TUNED FOR MORE</i>  </h6> 

![120064592-a5c83480-c075-11eb-89c1-78732ecaf8d3](https://gitlab.com/ORCA666/kcthijack/-/raw/main/images/PP.png)




