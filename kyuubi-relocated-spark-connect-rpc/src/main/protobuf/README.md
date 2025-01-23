proto files are copied from
https://github.com/apache/spark/tree/8a1f4acead0a580142152656913829700b710652/sql/connect/common/src/main/protobuf

and with one additional change in each proto file
```patch
- option java_package = "org.apache.spark.connect.proto"
+ option java_package = "org.apache.kyuubi.shaded.spark.connect.proto"
```
