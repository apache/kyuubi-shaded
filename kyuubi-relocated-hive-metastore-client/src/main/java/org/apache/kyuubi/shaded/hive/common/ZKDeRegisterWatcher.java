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

package org.apache.kyuubi.shaded.hive.common;

import org.apache.kyuubi.shaded.zookeeper.WatchedEvent;
import org.apache.kyuubi.shaded.zookeeper.Watcher;

/** The watcher class which sets the de-register flag when the given znode is deleted. */
public class ZKDeRegisterWatcher implements Watcher {
  private ZooKeeperHiveHelper zooKeeperHiveHelper;

  public ZKDeRegisterWatcher(ZooKeeperHiveHelper zooKeeperHiveHelper) {
    this.zooKeeperHiveHelper = zooKeeperHiveHelper;
  }

  @Override
  public void process(WatchedEvent event) {
    if (event.getType().equals(Watcher.Event.EventType.NodeDeleted)) {
      zooKeeperHiveHelper.deregisterZnode();
    }
  }
}
