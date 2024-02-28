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
package org.apache.hadoop.hive.metastore.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PrivilegedExceptionAction;
import java.util.Base64;
import java.util.Map;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.RealmChoiceCallback;
import javax.security.sasl.SaslException;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.SaslRpcServer;
import org.apache.hadoop.security.SaslRpcServer.AuthMethod;
import org.apache.hadoop.security.SecurityUtil;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.security.token.TokenIdentifier;
import org.apache.thrift.transport.TSaslClientTransport;
import org.apache.thrift.transport.TTransport;
import org.apache.thrift.transport.TTransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Functions that bridge Thrift's SASL transports to Hadoop's SASL callback handlers and
 * authentication classes. HIVE-11378 This class is not directly used anymore. It now exists only as
 * a shell to be extended by HadoopThriftAuthBridge23 in 0.23 shims. I have made it abstract to
 * avoid maintenance errors.
 */
public abstract class HadoopThriftAuthBridge {
  private static final Logger LOG = LoggerFactory.getLogger(HadoopThriftAuthBridge.class);

  // We want to have only one auth bridge.  In the past this was handled by ShimLoader, but since
  // we're no longer using that we'll do it here.
  private static volatile HadoopThriftAuthBridge self = null;

  public static HadoopThriftAuthBridge getBridge() {
    if (self == null) {
      synchronized (HadoopThriftAuthBridge.class) {
        if (self == null) self = new HadoopThriftAuthBridge23();
      }
    }
    return self;
  }

  public Client createClient() {
    return new Client();
  }

  /**
   * Read and return Hadoop SASL configuration which can be configured using "hadoop.rpc.protection"
   *
   * @param conf
   * @return Hadoop SASL configuration
   */
  public abstract Map<String, String> getHadoopSaslProperties(Configuration conf);

  public static class Client {
    /**
     * Create a client-side SASL transport that wraps an underlying transport.
     *
     * @param methodStr The authentication method to use. Currently only KERBEROS is supported.
     * @param principalConfig The Kerberos principal of the target server.
     * @param underlyingTransport The underlying transport mechanism, usually a TSocket.
     * @param saslProps the sasl properties to create the client with
     */
    public TTransport createClientTransport(
        String principalConfig,
        String host,
        String methodStr,
        String tokenStrForm,
        final TTransport underlyingTransport,
        final Map<String, String> saslProps)
        throws IOException {
      final AuthMethod method = AuthMethod.valueOf(AuthMethod.class, methodStr);

      TTransport saslTransport = null;
      switch (method) {
        case DIGEST:
          Token<DelegationTokenIdentifier> t = new Token<>();
          t.decodeFromUrlString(tokenStrForm);
          try {
            saslTransport =
                new TSaslClientTransport(
                    method.getMechanismName(),
                    null,
                    null,
                    SaslRpcServer.SASL_DEFAULT_REALM,
                    saslProps,
                    new SaslClientCallbackHandler(t),
                    underlyingTransport);
          } catch (TTransportException e) {
            e.printStackTrace();
          }
          return new TUGIAssumingTransport(saslTransport, UserGroupInformation.getCurrentUser());

        case KERBEROS:
          String serverPrincipal = SecurityUtil.getServerPrincipal(principalConfig, host);
          final String names[] = SaslRpcServer.splitKerberosName(serverPrincipal);
          if (names.length != 3) {
            throw new IOException(
                "Kerberos principal name does NOT have the expected hostname part: "
                    + serverPrincipal);
          }
          try {
            return UserGroupInformation.getCurrentUser()
                .doAs(
                    new PrivilegedExceptionAction<TUGIAssumingTransport>() {
                      @Override
                      public TUGIAssumingTransport run() throws IOException, TTransportException {
                        TTransport saslTransport =
                            new TSaslClientTransport(
                                method.getMechanismName(),
                                null,
                                names[0],
                                names[1],
                                saslProps,
                                null,
                                underlyingTransport);
                        return new TUGIAssumingTransport(
                            saslTransport, UserGroupInformation.getCurrentUser());
                      }
                    });
          } catch (InterruptedException | SaslException se) {
            throw new IOException("Could not instantiate SASL transport", se);
          }

        default:
          throw new IOException("Unsupported authentication method: " + method);
      }
    }

    private static class SaslClientCallbackHandler implements CallbackHandler {
      private final String userName;
      private final char[] userPassword;

      public SaslClientCallbackHandler(Token<? extends TokenIdentifier> token) {
        this.userName = encodeIdentifier(token.getIdentifier());
        this.userPassword = encodePassword(token.getPassword());
      }

      @Override
      public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
        NameCallback nc = null;
        PasswordCallback pc = null;
        RealmCallback rc = null;
        for (Callback callback : callbacks) {
          if (callback instanceof RealmChoiceCallback) {
            continue;
          } else if (callback instanceof NameCallback) {
            nc = (NameCallback) callback;
          } else if (callback instanceof PasswordCallback) {
            pc = (PasswordCallback) callback;
          } else if (callback instanceof RealmCallback) {
            rc = (RealmCallback) callback;
          } else {
            throw new UnsupportedCallbackException(callback, "Unrecognized SASL client callback");
          }
        }
        if (nc != null) {
          LOG.debug("SASL client callback: setting username: {}", userName);
          nc.setName(userName);
        }
        if (pc != null) {
          LOG.debug("SASL client callback: setting userPassword");
          pc.setPassword(userPassword);
        }
        if (rc != null) {
          LOG.debug("SASL client callback: setting realm: {}", rc.getDefaultText());
          rc.setText(rc.getDefaultText());
        }
      }

      static String encodeIdentifier(byte[] identifier) {
        return new String(Base64.getEncoder().encode(identifier), StandardCharsets.UTF_8);
      }

      static char[] encodePassword(byte[] password) {
        return Base64.getEncoder().encodeToString(password).toCharArray();
      }
    }
  }
}
