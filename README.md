# Wi-Fi-psw

解密`Windows`存储的`Wi-Fi`文件。

# Introduction

`Windows`的对于曾经连接过的`Wi-Fi`，会存储至本地的`xml`文件中，这些文件位于文件夹`C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces`中。

解密其中的`keyMaterial`字段即可得到明文的密码信息。

解密需要用到注册表，运行

```bash
reg save reg save HKLM\SYSTEM SystemBkup.hiv
reg save HKLM\SECURITY SECURITY.hiv
```

便可以得到解密需要用到的注册表，运行示例见[`main`](https://github.com/djh-sudo/Wi-Fi-psw/blob/main/src/main.cpp)。

## Other

用到了两个第三方库`Openssl`和`tinyXml2`，分别用于加解密和解析`xml`文件。同时头文件`wow64.hpp`用于解决`Windows`访问`System32`文件夹重定向[问题](https://stackoverflow.com/questions/885742/createfile-error-in-windows7)。