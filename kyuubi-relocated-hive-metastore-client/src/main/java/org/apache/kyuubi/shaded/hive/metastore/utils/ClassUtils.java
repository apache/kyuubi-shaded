/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.kyuubi.shaded.hive.metastore.utils;

import java.util.*;

/**
 * Operates on classes without using reflection.
 *
 * <p>This class handles invalid {@code null} inputs as best it can. Each method documents its
 * behavior in more detail.
 *
 * <p>The notion of a {@code canonical name} includes the human readable name for the type, for
 * example {@code int[]}. The non-canonical method variants work with the JVM names, such as {@code
 * [I}.
 *
 * @since 2.0
 */
// Copied from org.apache.commons:commons-lang3:3.12.0
public class ClassUtils {

  /** Maps primitive {@code Class}es to their corresponding wrapper {@code Class}. */
  private static final Map<Class<?>, Class<?>> primitiveWrapperMap = new HashMap<>();

  static {
    primitiveWrapperMap.put(Boolean.TYPE, Boolean.class);
    primitiveWrapperMap.put(Byte.TYPE, Byte.class);
    primitiveWrapperMap.put(Character.TYPE, Character.class);
    primitiveWrapperMap.put(Short.TYPE, Short.class);
    primitiveWrapperMap.put(Integer.TYPE, Integer.class);
    primitiveWrapperMap.put(Long.TYPE, Long.class);
    primitiveWrapperMap.put(Double.TYPE, Double.class);
    primitiveWrapperMap.put(Float.TYPE, Float.class);
    primitiveWrapperMap.put(Void.TYPE, Void.TYPE);
  }

  /**
   * Converts the specified primitive Class object to its corresponding wrapper Class object.
   *
   * <p>NOTE: From v2.2, this method handles {@code Void.TYPE}, returning {@code Void.TYPE}.
   *
   * @param cls the class to convert, may be null
   * @return the wrapper class for {@code cls} or {@code cls} if {@code cls} is not a primitive.
   *     {@code null} if null input.
   * @since 2.1
   */
  public static Class<?> primitiveToWrapper(final Class<?> cls) {
    Class<?> convertedClass = cls;
    if (cls != null && cls.isPrimitive()) {
      convertedClass = primitiveWrapperMap.get(cls);
    }
    return convertedClass;
  }
}
