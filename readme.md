## 保持HUST校园网不断的小工具

- 总所周知，Windows下校园网长时间连接(几个星期甚至半年)经常碰到校园网因为各种原因自动断开了，即使用了锐捷客户端也没用，放假回家后需要远程连接工位电脑可不能让它抽风。
- 不过Linux下用mentohust似乎基本没有这个问题。

这个小脚本利用校园网网页认证接口实现意外断网自动重连(仅对于校园网抽风导致丢失认证的情况，这种情况一般是手动联网就好，但是毕竟人不是总是在工位电脑旁边，所以有了这个脚本)。

使用方法：

1. 安装python
2. 安装所需的python库: ```pip install requests```
3. 运行一次connect_eportal.py脚本输入账号密码然后关闭，或者创建secret.cfg文件手动输入密码。
4. 在windows任务计划程序->任务计划程序库中创建基本任务。
5. 在这个新创建的任务中，"常规"选项卡中安全选项勾选"使用最高权限运行";选择不管用户是否登录都要运行;更改用户或组->高级->立即查找，选择合适的用户(也可以是"SYSTEM")。
6. 触发器设置为系统启动时启动程序(可以酌情添加其他触发器)；操作中设置启动程序，程序设置为自己安装好的python可执行文件路径(例如:"D:/path/to/python.exe")，添加参数指定这个python脚本文件"D:/path/to/connect_eportal.py"，起始于指定为这个脚本文件的所在目录。！！！注意当路径中有空格时不要漏掉双引号！！！
7. "条件"选项卡中看情况改动，不改似乎也问题不大一般。
8. 在"设置"选项卡中，取消勾选"如果任务运行时间超过以下时间，停止任务..."，如果此任务已运行，以下规则适用：请勿启动新实例。
9. 然后点确定保存设置，最后可以重启电脑测试一下效果，进行一下各种条件下的测试，确保有效，别把自己坑了。

目前还没有对各种情况做测试，可能有bug。