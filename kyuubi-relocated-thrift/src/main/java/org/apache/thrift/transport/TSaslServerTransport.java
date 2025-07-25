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

package org.apache.thrift.transport;

import java.lang.ref.WeakReference;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.WeakHashMap;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import org.apache.thrift.transport.sasl.NegotiationStatus;
import org.apache.thrift.transport.sasl.TSaslServerDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Wraps another Thrift <code>TTransport</code>, but performs SASL server negotiation on the call to
 * <code>open()</code>. This class will wrap ensuing communication over it, if a SASL QOP is
 * negotiated with the other party.
 */
public class TSaslServerTransport extends TSaslTransport {

  private static final Logger LOGGER = LoggerFactory.getLogger(TSaslServerTransport.class);

  private SaslServerFactory saslServerFactory = new JdkSaslServerFactory();

  /**
   * Mapping from SASL mechanism name -> all the parameters required to instantiate a SASL server.
   */
  private Map<String, TSaslServerDefinition> serverDefinitionMap = new HashMap<>();

  /**
   * Uses the given underlying transport. Assumes that addServerDefinition is called later.
   *
   * @param transport Transport underlying this one.
   */
  public TSaslServerTransport(TTransport transport) throws TTransportException {
    super(transport);
  }

  /**
   * Creates a <code>SaslServer</code> using the given SASL-specific parameters. See the Java
   * documentation for <code>Sasl.createSaslServer</code> for the details of the parameters.
   *
   * @param transport The underlying Thrift transport.
   */
  public TSaslServerTransport(
      String mechanism,
      String protocol,
      String serverName,
      Map<String, String> props,
      CallbackHandler cbh,
      TTransport transport)
      throws TTransportException {
    super(transport);
    addServerDefinition(mechanism, protocol, serverName, props, cbh);
  }

  private TSaslServerTransport(
      Map<String, TSaslServerDefinition> serverDefinitionMap, TTransport transport)
      throws TTransportException {
    super(transport);
    this.serverDefinitionMap.putAll(serverDefinitionMap);
  }

  /**
   * Add a supported server definition to this transport. See the Java documentation for <code>
   * Sasl.createSaslServer</code> for the details of the parameters.
   */
  public void addServerDefinition(
      String mechanism,
      String protocol,
      String serverName,
      Map<String, String> props,
      CallbackHandler cbh) {
    serverDefinitionMap.put(
        mechanism, new TSaslServerDefinition(mechanism, protocol, serverName, props, cbh));
  }

  public void setSaslServerFactory(SaslServerFactory f) {
    this.saslServerFactory = f;
  }

  @Override
  protected SaslRole getRole() {
    return SaslRole.SERVER;
  }

  /**
   * Performs the server side of the initial portion of the Thrift SASL protocol. Receives the
   * initial response from the client, creates a SASL server using the mechanism requested by the
   * client (if this server supports it), and sends the first challenge back to the client.
   */
  @Override
  protected void handleSaslStartMessage() throws TTransportException, SaslException {
    SaslResponse message = receiveSaslMessage();

    LOGGER.debug("Received start message with status {}", message.status);
    if (message.status != NegotiationStatus.START) {
      throw sendAndThrowMessage(
          NegotiationStatus.ERROR, "Expecting START status, received " + message.status);
    }

    // Get the mechanism name.
    String mechanismName = new String(message.payload, StandardCharsets.UTF_8);
    TSaslServerDefinition serverDefinition = serverDefinitionMap.get(mechanismName);
    LOGGER.debug("Received mechanism name '{}'", mechanismName);

    if (serverDefinition == null) {
      throw sendAndThrowMessage(
          NegotiationStatus.BAD, "Unsupported mechanism type " + mechanismName);
    }
    SaslServer saslServer = saslServerFactory.create(serverDefinition);
    setSaslServer(saslServer);
  }

  public interface SaslServerFactory {
    SaslServer create(TSaslServerDefinition d) throws SaslException;
  }

  public static class JdkSaslServerFactory implements SaslServerFactory {

    @Override
    public SaslServer create(TSaslServerDefinition d) throws SaslException {
      return Sasl.createSaslServer(d.mechanism, d.protocol, d.serverName, d.props, d.cbh);
    }
  }

  /**
   * <code>TTransportFactory</code> to create <code>TSaslServerTransports</code>. Ensures that a
   * given underlying <code>TTransport</code> instance receives the same <code>TSaslServerTransport
   * </code>. This is kind of an awful hack to work around the fact that Thrift is designed assuming
   * that <code>TTransport</code> instances are stateless, and thus the existing <code>TServers
   * </code> use different <code>TTransport</code> instances for input and output.
   */
  public static class Factory extends TTransportFactory {

    /**
     * This is the implementation of the awful hack described above. <code>WeakHashMap</code> is
     * used to ensure that we don't leak memory.
     */
    private static Map<TTransport, WeakReference<TSaslServerTransport>> transportMap =
        Collections.synchronizedMap(new WeakHashMap<>());

    /**
     * Mapping from SASL mechanism name -> all the parameters required to instantiate a SASL server.
     */
    private Map<String, TSaslServerDefinition> serverDefinitionMap = new HashMap<>();

    private SaslServerFactory saslServerFactory = new JdkSaslServerFactory();

    /** Create a new Factory. Assumes that <code>addServerDefinition</code> will be called later. */
    public Factory() {
      super();
    }

    /**
     * Create a new <code>Factory</code>, initially with the single server definition given. You may
     * still call <code>addServerDefinition</code> later. See the Java documentation for <code>
     * Sasl.createSaslServer</code> for the details of the parameters.
     */
    public Factory(
        String mechanism,
        String protocol,
        String serverName,
        Map<String, String> props,
        CallbackHandler cbh) {
      super();
      addServerDefinition(mechanism, protocol, serverName, props, cbh);
    }

    /**
     * Add a supported server definition to the transports created by this factory. See the Java
     * documentation for <code>Sasl.createSaslServer</code> for the details of the parameters.
     */
    public void addServerDefinition(
        String mechanism,
        String protocol,
        String serverName,
        Map<String, String> props,
        CallbackHandler cbh) {
      serverDefinitionMap.put(
          mechanism, new TSaslServerDefinition(mechanism, protocol, serverName, props, cbh));
    }

    public void setSaslServerFactory(SaslServerFactory f) {
      this.saslServerFactory = f;
    }

    /**
     * Get a new <code>TSaslServerTransport</code> instance, or reuse the existing one if a <code>
     * TSaslServerTransport</code> has already been created before using the given <code>TTransport
     * </code> as an underlying transport. This ensures that a given underlying transport instance
     * receives the same <code>TSaslServerTransport</code>.
     */
    @Override
    public TTransport getTransport(TTransport base) throws TTransportException {
      WeakReference<TSaslServerTransport> ret = transportMap.get(base);
      if (ret == null || ret.get() == null) {
        LOGGER.debug("transport map does not contain key {}", base);
        TSaslServerTransport t = new TSaslServerTransport(serverDefinitionMap, base);
        t.setSaslServerFactory(saslServerFactory);
        ret = new WeakReference<>(t);
        try {
          ret.get().open();
        } catch (TTransportException e) {
          LOGGER.debug("failed to open server transport", e);
          throw new RuntimeException(e);
        }
        transportMap.put(base, ret); // No need for putIfAbsent().
        // Concurrent calls to getTransport() will pass in different TTransports.
      } else {
        LOGGER.debug("transport map does contain key {}", base);
      }
      return ret.get();
    }
  }
}
