proto files are copied from
https://github.com/apache/spark/tree/v4.0.0-rc4/sql/connect/common/src/main/protobuf

and with one additional change in each proto file
```patch
- option java_package = "org.apache.spark.connect.proto"
+ option java_package = "org.apache.kyuubi.shaded.spark.connect.proto"
```
