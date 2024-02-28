/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.hive.metastore.utils;

import java.util.Map;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeysPublic;
import org.apache.hadoop.hive.metastore.api.MetaException;
import org.apache.hadoop.hive.metastore.security.HadoopThriftAuthBridge;
import org.apache.hadoop.security.SaslRpcServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MetaStoreUtils {

  private static final Logger LOG = LoggerFactory.getLogger(MetaStoreUtils.class);

  public static final String USER_NAME_HTTP_HEADER = "x-actor-username";

  /**
   * Catches exceptions that cannot be handled and wraps them in MetaException.
   *
   * @param e exception to wrap.
   * @throws MetaException wrapper for the exception
   */
  public static void throwMetaException(Exception e) throws MetaException {
    throw new MetaException("Got exception: " + e.getClass().getName() + " " + e.getMessage());
  }

  /**
   * Read and return the meta store Sasl configuration. Currently it uses the default Hadoop SASL
   * configuration and can be configured using "hadoop.rpc.protection" HADOOP-10211, made a backward
   * incompatible change due to which this call doesn't work with Hadoop 2.4.0 and later.
   *
   * @param conf
   * @return The SASL configuration
   */
  public static Map<String, String> getMetaStoreSaslProperties(Configuration conf, boolean useSSL) {
    // As of now Hive Meta Store uses the same configuration as Hadoop SASL configuration

    // If SSL is enabled, override the given value of "hadoop.rpc.protection" and set it to
    // "authentication"
    // This disables any encryption provided by SASL, since SSL already provides it
    String hadoopRpcProtectionVal = conf.get(CommonConfigurationKeysPublic.HADOOP_RPC_PROTECTION);
    String hadoopRpcProtectionAuth = SaslRpcServer.QualityOfProtection.AUTHENTICATION.toString();

    if (useSSL
        && hadoopRpcProtectionVal != null
        && !hadoopRpcProtectionVal.equals(hadoopRpcProtectionAuth)) {
      LOG.warn(
          "Overriding value of "
              + CommonConfigurationKeysPublic.HADOOP_RPC_PROTECTION
              + " setting it from "
              + hadoopRpcProtectionVal
              + " to "
              + hadoopRpcProtectionAuth
              + " because SSL is enabled");
      conf.set(CommonConfigurationKeysPublic.HADOOP_RPC_PROTECTION, hadoopRpcProtectionAuth);
    }
    return HadoopThriftAuthBridge.getBridge().getHadoopSaslProperties(conf);
  }

  /**
   * The config parameter can be like "path", "/path", "/path/", "path/*", "/path1/path2/*" and so
   * on. httpPath should end up as "/*", "/path/*" or "/path1/../pathN/*"
   *
   * @param httpPath
   * @return
   */
  public static String getHttpPath(String httpPath) {
    if (httpPath == null || httpPath.equals("")) {
      httpPath = "/*";
    } else {
      if (!httpPath.startsWith("/")) {
        httpPath = "/" + httpPath;
      }
      if (httpPath.endsWith("/")) {
        httpPath = httpPath + "*";
      }
      if (!httpPath.endsWith("/*")) {
        httpPath = httpPath + "/*";
      }
    }
    return httpPath;
  }
}
