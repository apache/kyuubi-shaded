/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.kyuubi.shaded.util;

public final class Signal {

  // Delegate to sun.misc.Signal.
  private final sun.misc.Signal iSignal;

  /* Returns the signal number */
  public int getNumber() {
    return iSignal.getNumber();
  }

  /**
   * Returns the signal name.
   *
   * @return the name of the signal.
   * @see sun.misc.Signal#Signal(String name)
   */
  public String getName() {
    return iSignal.getName();
  }

  /**
   * Compares the equality of two <code>Signal</code> objects.
   *
   * @param other the object to compare with.
   * @return whether two <code>Signal</code> objects are equal.
   */
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    }
    if (other == null || !(other instanceof Signal)) {
      return false;
    }
    Signal other1 = (Signal) other;
    return iSignal.equals(other1.iSignal);
  }

  /**
   * Returns a hashcode for this Signal.
   *
   * @return a hash code value for this object.
   */
  public int hashCode() {
    return getNumber();
  }

  /**
   * Returns a string representation of this signal. For example, "SIGINT" for an object constructed
   * using <code>new Signal ("INT")</code>.
   *
   * @return a string representation of the signal
   */
  public String toString() {
    return iSignal.toString();
  }

  /**
   * Constructs a signal from its name.
   *
   * @param name the name of the signal.
   * @exception IllegalArgumentException unknown signal
   * @see sun.misc.Signal#getName()
   */
  public Signal(String name) {
    iSignal = new sun.misc.Signal(name);
  }

  /**
   * Registers a signal handler.
   *
   * @param sig a signal
   * @param handler the handler to be registered with the given signal.
   * @return the old handler
   * @exception IllegalArgumentException the signal is in use by the VM
   * @see sun.misc.Signal#raise(sun.misc.Signal sig)
   * @see sun.misc.SignalHandler
   * @see sun.misc.SignalHandler#SIG_DFL
   * @see sun.misc.SignalHandler#SIG_IGN
   */
  public static synchronized SignalHandler handle(Signal sig, SignalHandler handler)
      throws IllegalArgumentException {
    sun.misc.SignalHandler oldHandler =
        sun.misc.Signal.handle(sig.iSignal, SunMiscHandler.of(sig, handler));
    return KyuubiSignalHandler.of(sig.iSignal, oldHandler);
  }

  /**
   * Raises a signal in the current process.
   *
   * @param sig a signal
   * @see sun.misc.Signal#handle(sun.misc.Signal sig, sun.misc.SignalHandler handler)
   */
  public static void raise(Signal sig) throws IllegalArgumentException {
    sun.misc.Signal.raise(sig.iSignal);
  }

  /*
   * Wrapper class to proxy a SignalHandler to a sun.misc.SignalHandler.
   */
  static final class SunMiscHandler implements sun.misc.SignalHandler {
    private final SignalHandler handler;
    private final Signal signal;

    static sun.misc.SignalHandler of(Signal signal, SignalHandler handler) {
      if (handler == SignalHandler.SIG_DFL) {
        return sun.misc.SignalHandler.SIG_DFL;
      } else if (handler == SignalHandler.SIG_IGN) {
        return sun.misc.SignalHandler.SIG_IGN;
      } else if (handler instanceof KyuubiSignalHandler) {
        return ((KyuubiSignalHandler) handler).iHandler;
      } else {
        return new SunMiscHandler(signal, handler);
      }
    }

    private SunMiscHandler(Signal signal, SignalHandler handler) {
      this.handler = handler;
      this.signal = signal;
    }

    @Override
    public void handle(sun.misc.Signal ignore) {
      handler.handle(signal);
    }
  }

  /*
   * Wrapper class to proxy a sun.misc.SignalHandler to a SignalHandler.
   */
  static final class KyuubiSignalHandler implements SignalHandler {
    private final sun.misc.Signal iSignal;
    private final sun.misc.SignalHandler iHandler;

    static SignalHandler of(sun.misc.Signal signal, sun.misc.SignalHandler handler) {
      if (handler == sun.misc.SignalHandler.SIG_DFL) {
        return SignalHandler.SIG_DFL;
      } else if (handler == sun.misc.SignalHandler.SIG_IGN) {
        return SignalHandler.SIG_IGN;
      } else if (handler instanceof SunMiscHandler) {
        return ((SunMiscHandler) handler).handler;
      } else {
        return new KyuubiSignalHandler(signal, handler);
      }
    }

    KyuubiSignalHandler(sun.misc.Signal iSignal, sun.misc.SignalHandler iHandler) {
      this.iSignal = iSignal;
      this.iHandler = iHandler;
    }

    @Override
    public void handle(Signal sig) {
      iHandler.handle(iSignal);
    }

    public String toString() {
      return iHandler.toString();
    }
  }
}
