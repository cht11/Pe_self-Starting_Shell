# Pe_self-Starting_Shell
Pe_self-Starting_Shell（PE自加载壳）
给了源码和exe，
但是用VS2019打开源码的时候，需要配置一些项目属性，所以另外给了整个项目文件的压缩包，包含项目配置文件，直接解压打开，就能移植项目属性。

另外，代码是一遍摸索一边写的，所以有点乱，望见谅~

PE自加载壳大概流程：将节区加密，添加或扩大最后一个节区，解密Shellcode放在文件末尾，修改OEP执行shellcode对文件解密，同时修复重定位、修复IAT表，然后返回原始OEP。
