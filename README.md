# IDA-Pacp-File-Loader

基于《The IDA Pro Book, 2nd Edition The Unofficial Guide to the Worlds Most Popular Disassembler (Chris Eagle)》(IDA权威指南) 书籍第18章"A pcap Loader for IDA" 改写。

## 增添特性：

* 在较新sdk版本上能够编译&运行。
* 添加代码注释，优化代码可读性。
* 增加节中表示数据包序号功能。

## 本地编译

* 将下载的IDA SDK文件复制到此目录下,命名为`idasdk`。
* 用`visual studio`打开`IDA-Pacp-File-Loader.sln`文件。
* Build Solution.
    编译好的dll在`x64/Debug_32`文件目录下,名字为`IDA-Pacp-File-Loader.dll`。


最后，将编译好的`IDA-Pacp-File-Loader.dll`文件放在`<IDA DIR>/loader/`目录下就OK了。

