# PcapParser



参数设置在Parameters.h



PACKET_COUNT：读取的报文个数（TCP/UDP），默认-1，全部读取

EPOCN_NUM：读取的时间窗口个数，默认-1，全部读取

EPOCH_LEN：时间窗口大小，单位：second

KEY_LEN：flow key字节数，可以是4，8，13，分别对应一、二、五元组



如何进行数据分析不生成数据？

```
make
./parser input_file
```



