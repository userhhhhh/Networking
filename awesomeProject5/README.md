# TLS协议

TLS协议是用于在网络上进行安全通信的协议，它的通信内容通过TLS记录（TLS Record）进行传输和管理。

一个标准的TLS记录包含以下几个部分：

1. **内容类型（Content Type）**（第1个字节）：
    - 表示这个记录的内容类型，例如数据、握手消息、警告等。常见的类型包括：
        - 0x14：ChangeCipherSpec
        - 0x15：Alert
        - 0x16：Handshake
        - 0x17：ApplicationData

2. **协议版本（Version）**（第2和第3个字节）：
    - 表示TLS协议的版本，例如TLS 1.0、TLS 1.2等。

3. **长度（Length）**（第4和第5个字节）：
    - 表示TLS记录数据部分的长度，以字节为单位。

4. **数据（Data）**：
    - 实际的TLS记录数据，其内容和结构取决于内容类型。
   - 具体内容可见：https://blog.csdn.net/weixin_46622350/article/details/120806194
   - 实现的内容在文章clienthello的图片中


