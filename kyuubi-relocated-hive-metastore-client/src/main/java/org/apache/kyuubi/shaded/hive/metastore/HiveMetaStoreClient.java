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

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.util.ReflectionUtils;
import org.apache.hadoop.util.StringUtils;
import org.apache.http.HttpException;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.protocol.HttpContext;
import org.apache.kyuubi.shaded.hive.metastore.api.MetaException;
import org.apache.kyuubi.shaded.hive.metastore.api.ThriftHiveMetastore;
import org.apache.kyuubi.shaded.hive.metastore.conf.MetastoreConf;
import org.apache.kyuubi.shaded.hive.metastore.conf.MetastoreConf.ConfVars;
import org.apache.kyuubi.shaded.hive.metastore.hooks.URIResolverHook;
import org.apache.kyuubi.shaded.hive.metastore.security.HadoopThriftAuthBridge;
import org.apache.kyuubi.shaded.hive.metastore.utils.JavaUtils;
import org.apache.kyuubi.shaded.hive.metastore.utils.MetaStoreUtils;
import org.apache.kyuubi.shaded.hive.metastore.utils.SecurityUtils;
import org.apache.thrift.TConfiguration;
import org.apache.thrift.TException;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.protocol.TCompactProtocol;
import org.apache.thrift.protocol.TProtocol;
import org.apache.thrift.transport.THttpClient;
import org.apache.thrift.transport.TSocket;
import org.apache.thrift.transport.TTransport;
import org.apache.thrift.transport.TTransportException;
import org.apache.thrift.transport.layered.TFramedTransport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Hive Metastore Client. The public implementation of IMetaStoreClient. Methods not inherited from
 * IMetaStoreClient are not public and can change. Hence this is marked as unstable. For users who
 * require retry mechanism when the connection between metastore and client is broken,
 * RetryingMetaStoreClient class should be used.
 */
@InterfaceAudience.Public
@InterfaceStability.Evolving
public class HiveMetaStoreClient implements IMetaStoreClient, AutoCloseable {

  ThriftHiveMetastore.Iface client = null;
  private TTransport transport = null;
  private boolean isConnected = false;
  private URI metastoreUris[];
  protected final Configuration
      conf; // Keep a copy of HiveConf so if Session conf changes, we may need to get a new HMS
  // client.
  private String tokenStrForm;
  private final boolean localMetaStore;
  private final URIResolverHook uriResolverHook;

  private Map<String, String> currentMetaVars;

  private static final AtomicInteger connCount = new AtomicInteger(0);

  // for thrift connects
  private int retries = 5;
  private long retryDelaySeconds = 0;

  protected static final Logger LOG = LoggerFactory.getLogger(HiveMetaStoreClient.class);

  public HiveMetaStoreClient(Configuration conf) throws MetaException {

    if (conf == null) {
      conf = MetastoreConf.newMetastoreConf();
      this.conf = conf;
    } else {
      this.conf = new Configuration(conf);
    }
    uriResolverHook = loadUriResolverHook();

    String msUri = MetastoreConf.getVar(conf, ConfVars.THRIFT_URIS);
    localMetaStore = MetastoreConf.isEmbeddedMetaStore(msUri);
    if (localMetaStore) {
      // instantiate the metastore server handler directly instead of connecting
      // through the network
      isConnected = true;
      return;
    }

    // get the number retries
    retries = MetastoreConf.getIntVar(conf, ConfVars.THRIFT_CONNECTION_RETRIES);
    retryDelaySeconds =
        MetastoreConf.getTimeVar(conf, ConfVars.CLIENT_CONNECT_RETRY_DELAY, TimeUnit.SECONDS);

    // user wants file store based configuration
    if (MetastoreConf.getVar(conf, ConfVars.THRIFT_URIS) != null) {
      resolveUris();
    } else {
      LOG.error("NOT getting uris from conf");
      throw new MetaException("MetaStoreURIs not found in conf file");
    }

    // finally open the store
    open();
  }

  private void resolveUris() throws MetaException {
    String thriftUris = MetastoreConf.getVar(conf, ConfVars.THRIFT_URIS);
    String serviceDiscoveryMode =
        MetastoreConf.getVar(conf, ConfVars.THRIFT_SERVICE_DISCOVERY_MODE);
    List<String> metastoreUrisString = null;

    // The metastore URIs can come from THRIFT_URIS directly or need to be fetched from the
    // Zookeeper
    try {
      if (serviceDiscoveryMode == null || serviceDiscoveryMode.trim().isEmpty()) {
        metastoreUrisString = Arrays.asList(thriftUris.split(","));
      } else if (serviceDiscoveryMode.equalsIgnoreCase("zookeeper")) {
        metastoreUrisString = new ArrayList<String>();
        // Add scheme to the bare URI we get.
        for (String s : MetastoreConf.getZKConfig(conf).getServerUris()) {
          metastoreUrisString.add("thrift://" + s);
        }
      } else {
        throw new IllegalArgumentException(
            "Invalid metastore dynamic service discovery mode " + serviceDiscoveryMode);
      }
    } catch (Exception e) {
      MetaStoreUtils.throwMetaException(e);
    }

    if (metastoreUrisString.isEmpty() && "zookeeper".equalsIgnoreCase(serviceDiscoveryMode)) {
      throw new MetaException(
          "No metastore service discovered in ZooKeeper. "
              + "Please ensure that at least one metastore server is online");
    }

    LOG.info("Resolved metastore uris: {}", metastoreUrisString);

    List<URI> metastoreURIArray = new ArrayList<URI>();
    try {
      for (String s : metastoreUrisString) {
        URI tmpUri = new URI(s);
        if (tmpUri.getScheme() == null) {
          throw new IllegalArgumentException("URI: " + s + " does not have a scheme");
        }
        if (uriResolverHook != null) {
          metastoreURIArray.addAll(uriResolverHook.resolveURI(tmpUri));
        } else {
          metastoreURIArray.add(tmpUri);
        }
      }
      metastoreUris = new URI[metastoreURIArray.size()];
      for (int j = 0; j < metastoreURIArray.size(); j++) {
        metastoreUris[j] = metastoreURIArray.get(j);
      }

      if (MetastoreConf.getVar(conf, ConfVars.THRIFT_URI_SELECTION).equalsIgnoreCase("RANDOM")) {
        List<URI> uriList = Arrays.asList(metastoreUris);
        Collections.shuffle(uriList);
        metastoreUris = uriList.toArray(new URI[uriList.size()]);
      }
    } catch (IllegalArgumentException e) {
      throw (e);
    } catch (Exception e) {
      MetaStoreUtils.throwMetaException(e);
    }
  }

  // multiple clients may initialize the hook at the same time
  private synchronized URIResolverHook loadUriResolverHook() throws IllegalStateException {

    String uriResolverClassName = MetastoreConf.getAsString(conf, ConfVars.URI_RESOLVER);
    if (uriResolverClassName.equals("")) {
      return null;
    } else {
      LOG.info("Loading uri resolver : " + uriResolverClassName);
      try {
        Class<?> uriResolverClass =
            Class.forName(uriResolverClassName, true, JavaUtils.getClassLoader());
        return (URIResolverHook) ReflectionUtils.newInstance(uriResolverClass, null);
      } catch (Exception e) {
        LOG.error("Exception loading uri resolver hook", e);
        return null;
      }
    }
  }

  /**
   * Swaps the first element of the metastoreUris array with a random element from the remainder of
   * the array.
   */
  private void promoteRandomMetaStoreURI() {
    if (metastoreUris.length <= 1) {
      return;
    }
    Random rng = new Random();
    int index = rng.nextInt(metastoreUris.length - 1) + 1;
    URI tmp = metastoreUris[0];
    metastoreUris[0] = metastoreUris[index];
    metastoreUris[index] = tmp;
  }

  public TTransport getTTransport() {
    return transport;
  }

  @Override
  public boolean isLocalMetaStore() {
    return localMetaStore;
  }

  @Override
  public void reconnect() throws MetaException {
    if (localMetaStore) {
      // For direct DB connections we don't yet support reestablishing connections.
      throw new MetaException(
          "Retries for direct MetaStore DB connections " + "are not supported by this client");
    } else {
      close();

      if (uriResolverHook != null) {
        // for dynamic uris, re-lookup if there are new metastore locations
        resolveUris();
      }

      if (MetastoreConf.getVar(conf, ConfVars.THRIFT_URI_SELECTION).equalsIgnoreCase("RANDOM")) {
        // Swap the first element of the metastoreUris[] with a random element from the rest
        // of the array. Rationale being that this method will generally be called when the default
        // connection has died and the default connection is likely to be the first array element.
        promoteRandomMetaStoreURI();
      }
      open();
    }
  }

  private <T extends TTransport> T configureThriftMaxMessageSize(T transport) {
    int maxThriftMessageSize =
        (int) MetastoreConf.getSizeVar(conf, ConfVars.THRIFT_METASTORE_CLIENT_MAX_MESSAGE_SIZE);
    if (maxThriftMessageSize > 0) {
      if (transport.getConfiguration() == null) {
        LOG.warn(
            "TTransport {} is returning a null Configuration, Thrift max message size is not getting configured",
            transport.getClass().getName());
        return transport;
      }
      transport.getConfiguration().setMaxMessageSize(maxThriftMessageSize);
    }
    return transport;
  }

  private Map<String, String> getAdditionalHeaders() {
    Map<String, String> headers = new HashMap<>();
    String keyValuePairs = MetastoreConf.getVar(conf, ConfVars.METASTORE_CLIENT_ADDITIONAL_HEADERS);
    try {
      String[] headerKeyValues = keyValuePairs.split(",");
      for (String header : headerKeyValues) {
        String[] parts = header.split("=");
        headers.put(parts[0].trim(), parts[1].trim());
      }
    } catch (Exception ex) {
      LOG.warn(
          "Could not parse the headers provided in " + ConfVars.METASTORE_CLIENT_ADDITIONAL_HEADERS,
          ex);
    }
    return headers;
  }

  /*
  Creates a THttpClient if HTTP mode is enabled. If Client auth mode is set to JWT,
  then the method fetches JWT from environment variable: HMS_JWT and sets in auth
  header in http request
   */
  private THttpClient createHttpClient(URI store, boolean useSSL)
      throws MetaException, TTransportException {
    String path = MetaStoreUtils.getHttpPath(MetastoreConf.getVar(conf, ConfVars.THRIFT_HTTP_PATH));
    String urlScheme;
    if (useSSL || Objects.equals(store.getScheme(), "https")) {
      urlScheme = "https://";
    } else {
      urlScheme = "http://";
    }
    String httpUrl = urlScheme + store.getHost() + ":" + store.getPort() + path;

    HttpClientBuilder httpClientBuilder = createHttpClientBuilder();
    THttpClient tHttpClient;
    try {
      if (useSSL) {
        String trustStorePath = MetastoreConf.getVar(conf, ConfVars.SSL_TRUSTSTORE_PATH).trim();
        if (trustStorePath.isEmpty()) {
          throw new IllegalArgumentException(
              ConfVars.SSL_TRUSTSTORE_PATH + " Not configured for SSL connection");
        }
        String trustStorePassword =
            MetastoreConf.getPassword(conf, MetastoreConf.ConfVars.SSL_TRUSTSTORE_PASSWORD);
        String trustStoreType = MetastoreConf.getVar(conf, ConfVars.SSL_TRUSTSTORE_TYPE).trim();
        String trustStoreAlgorithm =
            MetastoreConf.getVar(conf, ConfVars.SSL_TRUSTMANAGERFACTORY_ALGORITHM).trim();
        tHttpClient =
            SecurityUtils.getThriftHttpsClient(
                httpUrl,
                trustStorePath,
                trustStorePassword,
                trustStoreAlgorithm,
                trustStoreType,
                httpClientBuilder);
      } else {
        tHttpClient = new THttpClient(httpUrl, httpClientBuilder.build());
      }
    } catch (Exception e) {
      if (e instanceof TTransportException) {
        throw (TTransportException) e;
      } else {
        throw new MetaException(
            "Failed to create http transport client to url: " + httpUrl + ". Error:" + e);
      }
    }
    LOG.debug("Created thrift http client for URL: " + httpUrl);
    return configureThriftMaxMessageSize(tHttpClient);
  }

  protected HttpClientBuilder createHttpClientBuilder() throws MetaException {
    HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
    String authType = MetastoreConf.getVar(conf, ConfVars.METASTORE_CLIENT_AUTH_MODE);
    Map<String, String> additionalHeaders = getAdditionalHeaders();
    if (authType.equalsIgnoreCase("jwt")) {
      // fetch JWT token from environment and set it in Auth Header in HTTP request
      String jwtToken = System.getenv("HMS_JWT");
      if (jwtToken == null || jwtToken.isEmpty()) {
        LOG.debug("No jwt token set in environment variable: HMS_JWT");
        throw new MetaException(
            "For auth mode JWT, valid signed jwt token must be provided in the "
                + "environment variable HMS_JWT");
      }
      httpClientBuilder.addInterceptorFirst(
          new HttpRequestInterceptor() {
            @Override
            public void process(HttpRequest httpRequest, HttpContext httpContext)
                throws HttpException, IOException {
              httpRequest.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + jwtToken);
              for (Map.Entry<String, String> entry : additionalHeaders.entrySet()) {
                httpRequest.addHeader(entry.getKey(), entry.getValue());
              }
            }
          });
    } else {
      String user = MetastoreConf.getVar(conf, ConfVars.METASTORE_CLIENT_PLAIN_USERNAME);
      if (user == null || user.equals("")) {
        try {
          user = UserGroupInformation.getCurrentUser().getShortUserName();
        } catch (IOException e) {
          throw new MetaException("Failed to get client username from UGI");
        }
      }
      final String httpUser = user;
      httpClientBuilder.addInterceptorFirst(
          new HttpRequestInterceptor() {
            @Override
            public void process(HttpRequest httpRequest, HttpContext httpContext)
                throws HttpException, IOException {
              httpRequest.addHeader(MetaStoreUtils.USER_NAME_HTTP_HEADER, httpUser);
              for (Map.Entry<String, String> entry : additionalHeaders.entrySet()) {
                httpRequest.addHeader(entry.getKey(), entry.getValue());
              }
            }
          });
    }
    return httpClientBuilder;
  }

  private TTransport createBinaryClient(URI store, boolean useSSL)
      throws TTransportException, MetaException {
    TTransport binaryTransport = null;
    try {
      int clientSocketTimeout =
          (int)
              MetastoreConf.getTimeVar(conf, ConfVars.CLIENT_SOCKET_TIMEOUT, TimeUnit.MILLISECONDS);
      int connectionTimeout =
          (int)
              MetastoreConf.getTimeVar(
                  conf, ConfVars.CLIENT_CONNECTION_TIMEOUT, TimeUnit.MILLISECONDS);
      if (useSSL) {
        String trustStorePath = MetastoreConf.getVar(conf, ConfVars.SSL_TRUSTSTORE_PATH).trim();
        if (trustStorePath.isEmpty()) {
          throw new IllegalArgumentException(
              ConfVars.SSL_TRUSTSTORE_PATH + " Not configured for SSL connection");
        }
        String trustStorePassword =
            MetastoreConf.getPassword(conf, MetastoreConf.ConfVars.SSL_TRUSTSTORE_PASSWORD);
        String trustStoreType = MetastoreConf.getVar(conf, ConfVars.SSL_TRUSTSTORE_TYPE).trim();
        String trustStoreAlgorithm =
            MetastoreConf.getVar(conf, ConfVars.SSL_TRUSTMANAGERFACTORY_ALGORITHM).trim();
        binaryTransport =
            SecurityUtils.getSSLSocket(
                store.getHost(),
                store.getPort(),
                clientSocketTimeout,
                connectionTimeout,
                trustStorePath,
                trustStorePassword,
                trustStoreType,
                trustStoreAlgorithm);
      } else {
        binaryTransport =
            new TSocket(
                new TConfiguration(),
                store.getHost(),
                store.getPort(),
                clientSocketTimeout,
                connectionTimeout);
      }
      binaryTransport = createAuthBinaryTransport(store, binaryTransport);
    } catch (Exception e) {
      if (e instanceof TTransportException) {
        throw (TTransportException) e;
      } else {
        throw new MetaException(
            "Failed to create binary transport client to url: " + store + ". Error: " + e);
      }
    }
    LOG.debug("Created thrift binary client for URI: " + store);
    return configureThriftMaxMessageSize(binaryTransport);
  }

  private void open() throws MetaException {
    isConnected = false;
    TTransportException tte = null;
    MetaException recentME = null;
    boolean useSSL = MetastoreConf.getBoolVar(conf, ConfVars.USE_SSL);
    boolean useCompactProtocol =
        MetastoreConf.getBoolVar(conf, ConfVars.USE_THRIFT_COMPACT_PROTOCOL);
    String transportMode =
        MetastoreConf.getVar(conf, ConfVars.METASTORE_CLIENT_THRIFT_TRANSPORT_MODE);
    boolean isHttpTransportMode = transportMode.equalsIgnoreCase("http");

    for (int attempt = 0; !isConnected && attempt < retries; ++attempt) {
      for (URI store : metastoreUris) {
        LOG.info(
            "Trying to connect to metastore with URI ({}) in {} transport mode",
            store,
            transportMode);
        try {
          try {
            if (isHttpTransportMode) {
              transport = createHttpClient(store, useSSL);
            } else {
              transport = createBinaryClient(store, useSSL);
            }
          } catch (TTransportException te) {
            tte = te;
            throw new MetaException(te.toString());
          }

          final TProtocol protocol;
          if (useCompactProtocol) {
            protocol = new TCompactProtocol(transport);
          } else {
            protocol = new TBinaryProtocol(transport);
          }
          client = new ThriftHiveMetastore.Client(protocol);
          try {
            if (!transport.isOpen()) {
              transport.open();
              final int newCount = connCount.incrementAndGet();
              if (useSSL) {
                LOG.info(
                    "Opened an SSL connection to metastore, current connections: {}", newCount);
                if (LOG.isTraceEnabled()) {
                  LOG.trace(
                      "METASTORE SSL CONNECTION TRACE - open [{}]",
                      System.identityHashCode(this),
                      new Exception());
                }
              } else {
                LOG.info(
                    "Opened a connection to metastore, URI ({}) " + "current connections: {}",
                    store,
                    newCount);
                if (LOG.isTraceEnabled()) {
                  LOG.trace(
                      "METASTORE CONNECTION TRACE - open [{}]",
                      System.identityHashCode(this),
                      new Exception());
                }
              }
            }
            isConnected = true;
          } catch (TTransportException e) {
            tte = e;
            String errMsg =
                String.format(
                    "Failed to connect to the MetaStore Server URI (%s) in %s " + "transport mode",
                    store, transportMode);
            LOG.warn(errMsg);
            LOG.debug(errMsg, e);
          }
        } catch (MetaException e) {
          recentME = e;
          String errMsg =
              "Failed to connect to metastore with URI ("
                  + store
                  + ") transport mode:"
                  + transportMode
                  + " in attempt "
                  + attempt;
          LOG.error(errMsg, e);
        }
        if (isConnected) {
          break;
        }
      }
      // Wait before launching the next round of connection retries.
      if (!isConnected && retryDelaySeconds > 0) {
        try {
          LOG.info("Waiting " + retryDelaySeconds + " seconds before next connection attempt.");
          Thread.sleep(retryDelaySeconds * 1000);
        } catch (InterruptedException ignore) {
        }
      }
    }

    if (!isConnected) {
      // Either tte or recentME should be set but protect from a bug which causes both of them to
      // be null. When MetaException wraps TTransportException, tte will be set so stringify that
      // directly.
      String exceptionString = "Unknown exception";
      if (tte != null) {
        exceptionString = StringUtils.stringifyException(tte);
      } else if (recentME != null) {
        exceptionString = StringUtils.stringifyException(recentME);
      }
      throw new MetaException(
          "Could not connect to meta store using any of the URIs provided."
              + " Most recent failure: "
              + exceptionString);
    }

    snapshotActiveConf();
  }

  // wraps the underlyingTransport in the appropriate transport based on mode of authentication
  private TTransport createAuthBinaryTransport(URI store, TTransport underlyingTransport)
      throws MetaException {
    boolean isHttpTransportMode =
        MetastoreConf.getVar(conf, ConfVars.METASTORE_CLIENT_THRIFT_TRANSPORT_MODE)
            .equalsIgnoreCase("http");
    if (!isHttpTransportMode) {
      throw new IllegalArgumentException("HTTP mode is not supported");
    }
    Objects.requireNonNull(underlyingTransport, "Underlying transport should not be null");
    // default transport is the underlying one
    TTransport transport = underlyingTransport;
    boolean useFramedTransport =
        MetastoreConf.getBoolVar(conf, ConfVars.USE_THRIFT_FRAMED_TRANSPORT);
    boolean useSSL = MetastoreConf.getBoolVar(conf, ConfVars.USE_SSL);
    boolean useSasl = MetastoreConf.getBoolVar(conf, ConfVars.USE_THRIFT_SASL);
    String clientAuthMode = MetastoreConf.getVar(conf, ConfVars.METASTORE_CLIENT_AUTH_MODE);
    boolean usePasswordAuth = false;

    if (clientAuthMode != null) {
      usePasswordAuth = "PLAIN".equalsIgnoreCase(clientAuthMode);
    }
    if (usePasswordAuth) {
      // we are using PLAIN Sasl connection with user/password
      LOG.debug("HMSC::open(): Creating plain authentication thrift connection.");
      String userName = MetastoreConf.getVar(conf, ConfVars.METASTORE_CLIENT_PLAIN_USERNAME);

      if (null == userName || userName.isEmpty()) {
        throw new MetaException("No user specified for plain transport.");
      }

      // The password is not directly provided. It should be obtained from a keystore pointed
      // by configuration "hadoop.security.credential.provider.path".
      try {
        String passwd = null;
        char[] pwdCharArray = conf.getPassword(userName);
        if (null != pwdCharArray) {
          passwd = new String(pwdCharArray);
        }
        if (null == passwd) {
          throw new MetaException("No password found for user " + userName);
        }
        // Overlay the SASL transport on top of the base socket transport (SSL or non-SSL)
        transport =
            MetaStorePlainSaslHelper.getPlainTransport(userName, passwd, underlyingTransport);
      } catch (IOException | TTransportException sasle) {
        // IOException covers SaslException
        LOG.error("Could not create client transport", sasle);
        throw new MetaException(sasle.toString());
      }
    } else if (useSasl) {
      // Wrap thrift connection with SASL for secure connection.
      try {
        HadoopThriftAuthBridge.Client authBridge =
            HadoopThriftAuthBridge.getBridge().createClient();

        // check if we should use delegation tokens to authenticate
        // the call below gets hold of the tokens if they are set up by hadoop
        // this should happen on the map/reduce tasks if the client added the
        // tokens into hadoop's credential store in the front end during job
        // submission.
        String tokenSig = MetastoreConf.getVar(conf, ConfVars.TOKEN_SIGNATURE);
        // tokenSig could be null
        tokenStrForm = SecurityUtils.getTokenStrForm(tokenSig);

        if (tokenStrForm != null) {
          LOG.debug(
              "HMSC::open(): Found delegation token. Creating DIGEST-based thrift connection.");
          // authenticate using delegation tokens via the "DIGEST" mechanism
          transport =
              authBridge.createClientTransport(
                  null,
                  store.getHost(),
                  "DIGEST",
                  tokenStrForm,
                  underlyingTransport,
                  MetaStoreUtils.getMetaStoreSaslProperties(conf, useSSL));
        } else {
          LOG.debug(
              "HMSC::open(): Could not find delegation token. Creating KERBEROS-based thrift connection.");
          String principalConfig = MetastoreConf.getVar(conf, ConfVars.KERBEROS_PRINCIPAL);
          transport =
              authBridge.createClientTransport(
                  principalConfig,
                  store.getHost(),
                  "KERBEROS",
                  null,
                  underlyingTransport,
                  MetaStoreUtils.getMetaStoreSaslProperties(conf, useSSL));
        }
      } catch (IOException ioe) {
        LOG.error("Failed to create client transport", ioe);
        throw new MetaException(ioe.toString());
      }
    } else {
      if (useFramedTransport) {
        try {
          transport = new TFramedTransport(transport);
        } catch (TTransportException e) {
          LOG.error("Failed to create client transport", e);
          throw new MetaException(e.toString());
        }
      }
    }
    return transport;
  }

  private void snapshotActiveConf() {
    currentMetaVars = new HashMap<>(MetastoreConf.metaVars.length);
    for (ConfVars oneVar : MetastoreConf.metaVars) {
      currentMetaVars.put(oneVar.getVarname(), MetastoreConf.getAsString(conf, oneVar));
    }
  }

  @Override
  public void close() {
    isConnected = false;
    currentMetaVars = null;
    try {
      if (null != client) {
        client.shutdown();
        if ((transport == null) || !transport.isOpen()) {
          final int newCount = connCount.decrementAndGet();
          LOG.info("Closed a connection to metastore, current connections: {}", newCount);
        }
      }
    } catch (TException e) {
      LOG.debug("Unable to shutdown metastore client. Will try closing transport directly.", e);
    }
    // Transport would have got closed via client.shutdown(), so we dont need this, but
    // just in case, we make this call.
    if ((transport != null) && transport.isOpen()) {
      transport.close();
      final int newCount = connCount.decrementAndGet();
      LOG.info("Closed a connection to metastore, current connections: {}", newCount);
      if (LOG.isTraceEnabled()) {
        LOG.trace(
            "METASTORE CONNECTION TRACE - close [{}]",
            System.identityHashCode(this),
            new Exception());
      }
    }
  }

  @Override
  public String getDelegationToken(String owner, String renewerKerberosPrincipalName)
      throws MetaException, TException {
    // This is expected to be a no-op, so we will return null when we use local metastore.
    if (localMetaStore) {
      return null;
    }
    return client.get_delegation_token(owner, renewerKerberosPrincipalName);
  }
}
