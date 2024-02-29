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
package org.apache.kyuubi.hive.metastore.utils;

import java.lang.reflect.Constructor;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.apache.commons.lang3.ClassUtils;
import org.apache.kyuubi.hive.metastore.api.MetaException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JavaUtils {
  public static final Logger LOG = LoggerFactory.getLogger(JavaUtils.class);

  /**
   * Standard way of getting classloader in Hive code (outside of Hadoop).
   *
   * <p>Uses the context loader to get access to classpaths to auxiliary and jars added with 'add
   * jar' command. Falls back to current classloader.
   *
   * <p>In Hadoop-related code, we use Configuration.getClassLoader().
   *
   * @return the class loader
   */
  public static ClassLoader getClassLoader() {
    ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
    if (classLoader == null) {
      classLoader = JavaUtils.class.getClassLoader();
    }
    return classLoader;
  }

  @SuppressWarnings(value = "unchecked")
  public static <T> Class<? extends T> getClass(String className, Class<T> clazz)
      throws MetaException {
    try {
      return (Class<? extends T>) Class.forName(className, true, getClassLoader());
    } catch (ClassNotFoundException e) {
      throw new MetaException(className + " class not found");
    }
  }

  /**
   * Create an object of the given class.
   *
   * @param theClass
   * @param parameterTypes an array of parameterTypes for the constructor
   * @param initargs the list of arguments for the constructor
   */
  public static <T> T newInstance(Class<T> theClass, Class<?>[] parameterTypes, Object[] initargs) {
    // Perform some sanity checks on the arguments.
    if (parameterTypes.length != initargs.length) {
      throw new IllegalArgumentException(
          "Number of constructor parameter types doesn't match number of arguments");
    }
    for (int i = 0; i < parameterTypes.length; i++) {
      // initargs are boxed to Object, so we need to wrapper primitive types here.
      Class<?> clazz = ClassUtils.primitiveToWrapper(parameterTypes[i]);
      if (initargs[i] != null && !(clazz.isInstance(initargs[i]))) {
        throw new IllegalArgumentException(
            "Object : " + initargs[i] + " is not an instance of " + clazz);
      }
    }

    try {
      Constructor<T> meth = theClass.getDeclaredConstructor(parameterTypes);
      meth.setAccessible(true);
      return meth.newInstance(initargs);
    } catch (Exception e) {
      throw new RuntimeException("Unable to instantiate " + theClass.getName(), e);
    }
  }

  /** @return name of current host */
  public static String hostname() {
    try {
      return InetAddress.getLocalHost().getHostName();
    } catch (UnknownHostException e) {
      LOG.error("Unable to resolve my host name " + e.getMessage());
      throw new RuntimeException(e);
    }
  }
}
