# HandleUtilize
  * 结束一个隐藏的或者受保护的进程（支持抹去PspCidTable全局句柄表项的进程，有进程Object回调保护的进程，PP/PPL保护的进程）: ```-p <process path>``` 
![img](https://img2023.cnblogs.com/blog/2052882/202212/2052882-20221210171018867-1924361763.png)

* 关闭所有PP/PPL保护：```-killPPL```
![img](https://img2023.cnblogs.com/blog/2052882/202212/2052882-20221210171331430-856588768.png)

* 枚举系统所有的句柄信息```-e```
![img](https://img2023.cnblogs.com/blog/2052882/202212/2052882-20221210171520766-1940326286.png)
* 枚举PspCidTable获取系统所有的进程和线程信息，但是这并一定是准确的。因为有可能进程或线程的PspCidTable表中的条目被抹去了。```-CidTable```
![img](https://img2023.cnblogs.com/blog/2052882/202212/2052882-20221211215502743-1225054806.png)
