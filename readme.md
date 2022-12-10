# HandleUtilize
  * 结束一个隐藏的或者受保护的进程（支持抹去PspCidTable全局句柄表项的进程，有进程Object回调保护的进程，PP/PPL保护的进程）: ```-p <process path>``` 
![img](https://img2023.cnblogs.com/blog/2052882/202212/2052882-20221210171018867-1924361763.png)

* 关闭所有PP/PPL保护：```-killPPL```
![img](https://img2023.cnblogs.com/blog/2052882/202212/2052882-20221210171331430-856588768.png)

* 枚举系统所有的句柄信息```-e```
![img](https://img2023.cnblogs.com/blog/2052882/202212/2052882-20221210171520766-1940326286.png)