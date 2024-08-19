proto files are copied from
https://github.com/apache/spark/tree/5b2d2149b615acdd8730547a1f24c2b637222545/sql/connect/common/src/main/protobuf

and with one additional change in each proto file
```patch
- option java_package = "org.apache.spark.connect.proto"
+ option java_package = "org.apache.kyuubi.shaded.spark.connect.proto"
```
