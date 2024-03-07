/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.kyuubi.shaded.hive.metastore;

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;
import org.apache.kyuubi.shaded.hive.metastore.annotation.NoReconnect;
import org.apache.kyuubi.shaded.hive.metastore.api.MetaException;
import org.apache.kyuubi.shaded.thrift.TException;

/** Wrapper around hive metastore thrift api */
@InterfaceAudience.Public
@InterfaceStability.Evolving
public interface IMetaStoreClient extends AutoCloseable {

  /**
   * Returns true if the current client is using an in process metastore (local metastore).
   *
   * @return
   */
  boolean isLocalMetaStore();

  /** Tries to reconnect this MetaStoreClient to the MetaStore. */
  void reconnect() throws MetaException;

  /** close connection to meta store */
  @NoReconnect
  void close();

  /**
   * This is expected to be a no-op when in local mode, which means that the implementation will
   * return null.
   *
   * @param owner the intended owner for the token
   * @param renewerKerberosPrincipalName
   * @return the string of the token
   * @throws MetaException
   * @throws TException
   */
  String getDelegationToken(String owner, String renewerKerberosPrincipalName)
      throws MetaException, TException;
}
