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
package org.apache.kyuubi.shaded.hive.metastore.conf;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.alias.CredentialProviderFactory;
import org.apache.kyuubi.shaded.hive.common.ZooKeeperHiveHelper;
import org.apache.kyuubi.shaded.hive.metastore.utils.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A set of definitions of config values used by the Metastore. One of the key aims of this class is
 * to provide backwards compatibility with existing Hive configuration keys while allowing the
 * metastore to have its own, Hive independent keys. For this reason access to the underlying
 * Configuration object should always be done via the static methods provided here rather than
 * directly via {@link Configuration#get(String)} and {@link Configuration#set(String, String)}. All
 * the methods of this class will handle checking both the MetastoreConf key and the Hive key. The
 * algorithm is, on reads, to check first the MetastoreConf key, then the Hive key, then return the
 * default if neither are set. On write the Metastore key only is set.
 *
 * <p>This class does not extend Configuration. Rather it provides static methods for operating on a
 * Configuration object. This allows it to work on HiveConf objects, which otherwise would not be
 * the case.
 */
public class MetastoreConf {

  private static final Logger LOG = LoggerFactory.getLogger(MetastoreConf.class);
  private static final Pattern TIME_UNIT_SUFFIX = Pattern.compile("([0-9]+)([a-zA-Z]+)");

  private static final Map<String, ConfVars> metaConfs = new HashMap<>();
  private static volatile URL hiveSiteURL = null;
  private static URL hiveDefaultURL = null;
  private static URL hiveMetastoreSiteURL = null;
  private static URL metastoreSiteURL = null;
  private static AtomicBoolean beenDumped = new AtomicBoolean();

  private static Map<String, ConfVars> keyToVars;

  static {
    keyToVars = new HashMap<>(ConfVars.values().length * 2);
    for (ConfVars var : ConfVars.values()) {
      keyToVars.put(var.varname, var);
      keyToVars.put(var.hiveName, var);
    }
  }

  static final String TEST_ENV_WORKAROUND = "metastore.testing.env.workaround.dont.ever.set.this.";

  private static class TimeValue {
    final long val;
    final TimeUnit unit;

    private TimeValue(long val, TimeUnit unit) {
      this.val = val;
      this.unit = unit;
    }

    @Override
    public String toString() {
      switch (unit) {
        case NANOSECONDS:
          return Long.toString(val) + "ns";
        case MICROSECONDS:
          return Long.toString(val) + "us";
        case MILLISECONDS:
          return Long.toString(val) + "ms";
        case SECONDS:
          return Long.toString(val) + "s";
        case MINUTES:
          return Long.toString(val) + "m";
        case HOURS:
          return Long.toString(val) + "h";
        case DAYS:
          return Long.toString(val) + "d";
      }
      throw new RuntimeException("Unknown time unit " + unit);
    }
  }

  /**
   * Metastore related options that the db is initialized against. When a conf var in this is list
   * is changed, the metastore instance for the CLI will be recreated so that the change will take
   * effect. TODO - I suspect the vast majority of these don't need to be here. But it requires
   * testing before just pulling them out.
   */
  public static final MetastoreConf.ConfVars[] metaVars = {
    ConfVars.THRIFT_URIS,
    ConfVars.THRIFT_ZOOKEEPER_CLIENT_PORT,
    ConfVars.THRIFT_ZOOKEEPER_NAMESPACE,
    ConfVars.THRIFT_CONNECTION_RETRIES,
    ConfVars.THRIFT_FAILURE_RETRIES,
    ConfVars.CLIENT_CONNECT_RETRY_DELAY,
    ConfVars.CLIENT_SOCKET_TIMEOUT,
    ConfVars.CLIENT_SOCKET_LIFETIME,
    ConfVars.KERBEROS_PRINCIPAL,
    ConfVars.USE_THRIFT_SASL,
    ConfVars.METASTORE_CLIENT_AUTH_MODE,
    ConfVars.METASTORE_CLIENT_PLAIN_USERNAME
  };

  /** User configurable Metastore vars */
  private static final MetastoreConf.ConfVars[] metaConfVars = {ConfVars.CLIENT_SOCKET_TIMEOUT};

  static {
    for (ConfVars confVar : metaConfVars) {
      metaConfs.put(confVar.varname, confVar);
      metaConfs.put(confVar.hiveName, confVar);
    }
  }

  /** Variables that we should never print the value of for security reasons. */
  private static final Set<String> unprintables =
      StringUtils.asSet(
          ConfVars.SSL_KEYSTORE_PASSWORD.varname,
          ConfVars.SSL_KEYSTORE_PASSWORD.hiveName,
          ConfVars.SSL_TRUSTSTORE_PASSWORD.varname,
          ConfVars.SSL_TRUSTSTORE_PASSWORD.hiveName);

  public static ConfVars getMetaConf(String name) {
    return metaConfs.get(name);
  }

  public enum ConfVars {
    // alpha order, PLEASE!
    CLIENT_CONNECT_RETRY_DELAY(
        "metastore.client.connect.retry.delay",
        "hive.metastore.client.connect.retry.delay",
        1,
        TimeUnit.SECONDS,
        "Number of seconds for the client to wait between consecutive connection attempts"),
    CLIENT_KERBEROS_PRINCIPAL(
        "metastore.client.kerberos.principal",
        "hive.metastore.client.kerberos.principal",
        "", // E.g. "hive-metastore/_HOST@EXAMPLE.COM".
        "The Kerberos principal associated with the HA cluster of hcat_servers."),
    CLIENT_SOCKET_LIFETIME(
        "metastore.client.socket.lifetime",
        "hive.metastore.client.socket.lifetime",
        0,
        TimeUnit.SECONDS,
        "MetaStore Client socket lifetime in seconds. After this time is exceeded, client\n"
            + "reconnects on the next MetaStore operation. A value of 0s means the connection\n"
            + "has an infinite lifetime."),
    CLIENT_SOCKET_TIMEOUT(
        "metastore.client.socket.timeout",
        "hive.metastore.client.socket.timeout",
        600,
        TimeUnit.SECONDS,
        "MetaStore Client socket timeout in seconds"),
    CLIENT_CONNECTION_TIMEOUT(
        "metastore.client.connection.timeout",
        "hive.metastore.client.connection.timeout",
        600,
        TimeUnit.SECONDS,
        "MetaStore Client connection timeout in seconds"),
    DUMP_CONFIG_ON_CREATION(
        "metastore.dump.config.on.creation",
        "metastore.dump.config.on.creation",
        true,
        "If true, a printout of the config file (minus sensitive values) will be dumped to the "
            + "log whenever newMetastoreConf() is called.  Can produce a lot of logs"),
    KERBEROS_PRINCIPAL(
        "metastore.kerberos.principal",
        "hive.metastore.kerberos.principal",
        "hive-metastore/_HOST@EXAMPLE.COM",
        "The service principal for the metastore Thrift server. \n"
            + "The special string _HOST will be replaced automatically with the correct host name."),
    SSL_KEYSTORE_PASSWORD(
        "metastore.keystore.password",
        "hive.metastore.keystore.password",
        "",
        "Metastore SSL certificate keystore password."),
    SSL_TRUSTSTORE_PATH(
        "metastore.truststore.path",
        "hive.metastore.truststore.path",
        "",
        "Metastore SSL certificate truststore location."),
    SSL_TRUSTSTORE_PASSWORD(
        "metastore.truststore.password",
        "hive.metastore.truststore.password",
        "",
        "Metastore SSL certificate truststore password."),
    SSL_TRUSTSTORE_TYPE(
        "metastore.truststore.type",
        "hive.metastore.truststore.type",
        "",
        "Metastore SSL certificate truststore type."),
    SSL_TRUSTMANAGERFACTORY_ALGORITHM(
        "metastore.trustmanagerfactory.algorithm",
        "hive.metastore.trustmanagerfactory.algorithm",
        "",
        "Metastore SSL certificate truststore algorithm."),
    THRIFT_TRANSPORT_MODE(
        "metastore.server.thrift.transport.mode",
        "hive.metastore.server.thrift.transport.mode",
        "binary",
        "Transport mode for thrift server in Metastore. Can be binary or http"),
    THRIFT_HTTP_PATH(
        "metastore.server.thrift.http.path",
        "hive.metastore.server.thrift.http.path",
        "metastore",
        "Path component of URL endpoint when in HTTP mode"),
    THRIFT_CONNECTION_RETRIES(
        "metastore.connect.retries",
        "hive.metastore.connect.retries",
        3,
        "Number of retries while opening a connection to metastore"),
    THRIFT_FAILURE_RETRIES(
        "metastore.failure.retries",
        "hive.metastore.failure.retries",
        1,
        "Number of retries upon failure of Thrift metastore calls"),
    THRIFT_URIS(
        "metastore.thrift.uris",
        "hive.metastore.uris",
        "",
        "URIs Used by metastore client to connect to remotemetastore\n."
            + "If dynamic service discovery mode is set, the URIs are used to connect to the"
            + " corresponding service discovery servers e.g. a zookeeper. Otherwise they are "
            + "used as URIs for remote metastore."),
    THRIFT_METASTORE_CLIENT_MAX_MESSAGE_SIZE(
        "metastore.thrift.client.max.message.size",
        "hive.thrift.client.max.message.size",
        "1gb",
        new SizeValidator(-1L, true, (long) Integer.MAX_VALUE, true),
        "Thrift client configuration for max message size. 0 or -1 will use the default defined in the Thrift "
            + "library. The upper limit is 2147483648 bytes (or 2gb)."),
    THRIFT_SERVICE_DISCOVERY_MODE(
        "metastore.service.discovery.mode",
        "hive.metastore.service.discovery.mode",
        "",
        "Specifies which dynamic service discovery method to use. Currently we support only "
            + "\"zookeeper\" to specify ZooKeeper based service discovery."),
    THRIFT_ZOOKEEPER_CLIENT_PORT(
        "metastore.zookeeper.client.port",
        "hive.zookeeper.client.port",
        "2181",
        "The port of ZooKeeper servers to talk to.\n"
            + "If the list of Zookeeper servers specified in hive.metastore.thrift.uris"
            + " does not contain port numbers, this value is used."),
    THRIFT_ZOOKEEPER_SESSION_TIMEOUT(
        "metastore.zookeeper.session.timeout",
        "hive.zookeeper.session.timeout",
        120000L,
        TimeUnit.MILLISECONDS,
        new TimeValidator(TimeUnit.MILLISECONDS),
        "ZooKeeper client's session timeout (in milliseconds). The client is disconnected\n"
            + "if a heartbeat is not sent in the timeout."),
    THRIFT_ZOOKEEPER_CONNECTION_TIMEOUT(
        "metastore.zookeeper.connection.timeout",
        "hive.zookeeper.connection.timeout",
        15L,
        TimeUnit.SECONDS,
        new TimeValidator(TimeUnit.SECONDS),
        "ZooKeeper client's connection timeout in seconds. "
            + "Connection timeout * hive.metastore.zookeeper.connection.max.retries\n"
            + "with exponential backoff is when curator client deems connection is lost to zookeeper."),
    THRIFT_ZOOKEEPER_NAMESPACE(
        "metastore.zookeeper.namespace",
        "hive.zookeeper.namespace",
        "hive_metastore",
        "The parent node under which all ZooKeeper nodes for metastores are created."),
    THRIFT_ZOOKEEPER_CONNECTION_MAX_RETRIES(
        "metastore.zookeeper.connection.max.retries",
        "hive.zookeeper.connection.max.retries",
        3,
        "Max number of times to retry when connecting to the ZooKeeper server."),
    THRIFT_ZOOKEEPER_CONNECTION_BASESLEEPTIME(
        "metastore.zookeeper.connection.basesleeptime",
        "hive.zookeeper.connection.basesleeptime",
        1000L,
        TimeUnit.MILLISECONDS,
        new TimeValidator(TimeUnit.MILLISECONDS),
        "Initial amount of time (in milliseconds) to wait between retries\n"
            + "when connecting to the ZooKeeper server when using ExponentialBackoffRetry policy."),
    THRIFT_URI_SELECTION(
        "metastore.thrift.uri.selection",
        "hive.metastore.uri.selection",
        "RANDOM",
        new StringSetValidator("RANDOM", "SEQUENTIAL"),
        "Determines the selection mechanism used by metastore client to connect to remote "
            + "metastore.  SEQUENTIAL implies that the first valid metastore from the URIs specified "
            + "through hive.metastore.uris will be picked.  RANDOM implies that the metastore "
            + "will be picked randomly"),
    TOKEN_SIGNATURE(
        "metastore.token.signature",
        "hive.metastore.token.signature",
        "",
        "The delegation token service name to match when selecting a token from the current user's tokens."),
    URI_RESOLVER(
        "metastore.uri.resolver",
        "hive.metastore.uri.resolver",
        "",
        "If set, fully qualified class name of resolver for hive metastore uri's"),
    // TODO: Should we have a separate config for the metastoreclient or THRIFT_TRANSPORT_MODE
    // would suffice ?
    METASTORE_CLIENT_THRIFT_TRANSPORT_MODE(
        "metastore.client.thrift.transport.mode",
        "hive.metastore.client.thrift.transport.mode",
        "binary",
        "Transport mode to be used by the metastore client. It should be the same as "
            + THRIFT_TRANSPORT_MODE),
    USE_SSL(
        "metastore.use.SSL",
        "hive.metastore.use.SSL",
        false,
        "Set this to true for using SSL encryption in HMS server."),
    // We should somehow unify next two options.
    USE_THRIFT_SASL(
        "metastore.sasl.enabled",
        "hive.metastore.sasl.enabled",
        false,
        "If true, the metastore Thrift interface will be secured with SASL. Clients must authenticate with Kerberos."),
    METASTORE_CLIENT_AUTH_MODE(
        "metastore.client.auth.mode",
        "hive.metastore.client.auth.mode",
        "NOSASL",
        new StringSetValidator("NOSASL", "PLAIN", "KERBEROS", "JWT"),
        "If PLAIN, clients will authenticate using plain authentication, by providing username"
            + " and password. Any other value is ignored right now but may be used later."
            + "If JWT- Supported only in HTTP transport mode. If set, HMS Client will pick the value of JWT from "
            + "environment variable HMS_JWT and set it in Authorization header in http request"),
    METASTORE_CLIENT_ADDITIONAL_HEADERS(
        "metastore.client.http.additional.headers",
        "hive.metastore.client.http.additional.headers",
        "",
        "Comma separated list of headers which are passed to the metastore service in the http headers"),
    METASTORE_CLIENT_PLAIN_USERNAME(
        "metastore.client.plain.username",
        "hive.metastore.client.plain.username",
        "",
        "The username used by the metastore client when "
            + METASTORE_CLIENT_AUTH_MODE
            + " is true. The password is obtained from "
            + CredentialProviderFactory.CREDENTIAL_PROVIDER_PATH
            + " using username as the "
            + "alias."),
    USE_THRIFT_FRAMED_TRANSPORT(
        "metastore.thrift.framed.transport.enabled",
        "hive.metastore.thrift.framed.transport.enabled",
        false,
        "If true, the metastore Thrift interface will use TFramedTransport. When false (default) a standard TTransport is used."),
    USE_THRIFT_COMPACT_PROTOCOL(
        "metastore.thrift.compact.protocol.enabled",
        "hive.metastore.thrift.compact.protocol.enabled",
        false,
        "If true, the metastore Thrift interface will use TCompactProtocol. When false (default) TBinaryProtocol will be used.\n"
            + "Setting it to true will break compatibility with older clients running TBinaryProtocol.");

    private final String varname;
    private final String hiveName;
    private final Object defaultVal;
    private final Validator validator;
    private final boolean caseSensitive;
    private final String description;
    private String deprecatedName = null;
    private String hiveDeprecatedName = null;

    ConfVars(String varname, String hiveName, String defaultVal, String description) {
      this.varname = varname;
      this.hiveName = hiveName;
      this.defaultVal = defaultVal;
      validator = null;
      caseSensitive = false;
      this.description = description;
    }

    ConfVars(
        String varname,
        String hiveName,
        String defaultVal,
        Validator validator,
        String description) {
      this.varname = varname;
      this.hiveName = hiveName;
      this.defaultVal = defaultVal;
      this.validator = validator;
      caseSensitive = false;
      this.description = description;
    }

    ConfVars(
        String varname,
        String hiveName,
        String defaultVal,
        boolean caseSensitive,
        String description) {
      this.varname = varname;
      this.hiveName = hiveName;
      this.defaultVal = defaultVal;
      validator = null;
      this.caseSensitive = caseSensitive;
      this.description = description;
    }

    ConfVars(String varname, String hiveName, long defaultVal, String description) {
      this.varname = varname;
      this.hiveName = hiveName;
      this.defaultVal = defaultVal;
      validator = null;
      caseSensitive = false;
      this.description = description;
    }

    ConfVars(
        String varname, String hiveName, long defaultVal, Validator validator, String description) {
      this.varname = varname;
      this.hiveName = hiveName;
      this.defaultVal = defaultVal;
      this.validator = validator;
      caseSensitive = false;
      this.description = description;
    }

    ConfVars(
        String varname,
        String hiveName,
        long defaultVal,
        Validator validator,
        String description,
        String deprecatedName,
        String hiveDeprecatedName) {
      this.varname = varname;
      this.hiveName = hiveName;
      this.defaultVal = defaultVal;
      this.validator = validator;
      caseSensitive = false;
      this.description = description;
      this.deprecatedName = deprecatedName;
      this.hiveDeprecatedName = hiveDeprecatedName;
    }

    ConfVars(String varname, String hiveName, boolean defaultVal, String description) {
      this.varname = varname;
      this.hiveName = hiveName;
      this.defaultVal = defaultVal;
      validator = null;
      caseSensitive = false;
      this.description = description;
    }

    ConfVars(String varname, String hiveName, double defaultVal, String description) {
      this.varname = varname;
      this.hiveName = hiveName;
      this.defaultVal = defaultVal;
      validator = null;
      caseSensitive = false;
      this.description = description;
    }

    ConfVars(String varname, String hiveName, long defaultVal, TimeUnit unit, String description) {
      this.varname = varname;
      this.hiveName = hiveName;
      this.defaultVal = new TimeValue(defaultVal, unit);
      validator = new TimeValidator(unit);
      caseSensitive = false;
      this.description = description;
    }

    ConfVars(
        String varname,
        String hiveName,
        long defaultVal,
        TimeUnit unit,
        Validator validator,
        String description) {
      this.varname = varname;
      this.hiveName = hiveName;
      this.defaultVal = new TimeValue(defaultVal, unit);
      this.validator = validator;
      caseSensitive = false;
      this.description = description;
    }

    public void validate(String value) throws IllegalArgumentException {
      if (validator != null) {
        validator.validate(value);
      }
    }

    public boolean isCaseSensitive() {
      return caseSensitive;
    }

    /**
     * If you are calling this, you're probably doing it wrong. You shouldn't need to use the
     * underlying variable name. Use one of the getVar methods instead. Only use this if you are
     * 100% sure you know you're doing. The reason for this is that MetastoreConf goes to a lot of
     * trouble to make sure it checks both Hive and Metastore values for config keys. If you call
     * {@link Configuration#get(String)} you are undermining that.
     *
     * @return variable name
     */
    public String getVarname() {
      return varname;
    }

    /**
     * Use this method if you need to set a system property and are going to instantiate the
     * configuration file via HiveConf. This is because HiveConf only looks for values it knows, so
     * it will miss all of the metastore.* ones. Do not use this to explicitly set or get the
     * underlying config value unless you are 100% sure you know what you're doing. The reason for
     * this is that MetastoreConf goes to a lot of trouble to make sure it checks both Hive and
     * Metastore values for config keys. If you call {@link Configuration#get(String)} you are
     * undermining that.
     *
     * @return hive.* configuration key
     */
    public String getHiveName() {
      return hiveName;
    }

    public Object getDefaultVal() {
      return defaultVal;
    }

    public String getDescription() {
      return description;
    }

    /**
     * This is useful if you need the variable name for a LOG message or {@link
     * System#setProperty(String, String)}, beware however that you should only use this with
     * setProperty if you're going to create a configuration via {@link
     * MetastoreConf#newMetastoreConf()}. If you are going to create it with HiveConf, then use
     * {@link #getHiveName()}.
     *
     * @return metastore.* configuration key
     */
    @Override
    public String toString() {
      return varname;
    }
  }

  // Make sure no one calls this
  private MetastoreConf() {
    throw new RuntimeException("You should never be creating one of these!");
  }

  public static Configuration newMetastoreConf() {
    return newMetastoreConf(new Configuration());
  }

  public static Configuration newMetastoreConf(Configuration conf) {

    ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
    if (classLoader == null) {
      classLoader = MetastoreConf.class.getClassLoader();
    }
    // We don't add this to the resources because we don't want to read config values from it.
    // But we do find it because we want to remember where it is for later in case anyone calls
    // getHiveDefaultLocation().
    hiveDefaultURL = classLoader.getResource("hive-default.xml");

    // Add in hive-site.xml.  We add this first so that it gets overridden by the new metastore
    // specific files if they exist.
    if (hiveSiteURL == null) {
      /*
       * this 'if' is pretty lame - QTestUtil.QTestUtil() uses hiveSiteURL to load a specific
       * hive-site.xml from data/conf/<subdir> so this makes it follow the same logic - otherwise
       * HiveConf and MetastoreConf may load different hive-site.xml  ( For example,
       * HiveConf uses data/conf/tez/hive-site.xml and MetastoreConf data/conf/hive-site.xml)
       */
      hiveSiteURL = findConfigFile(classLoader, "hive-site.xml");
    }
    if (hiveSiteURL != null) {
      conf.addResource(hiveSiteURL);
    }

    // Now add hivemetastore-site.xml.  Again we add this before our own config files so that the
    // newer overrides the older.
    hiveMetastoreSiteURL = findConfigFile(classLoader, "hivemetastore-site.xml");
    if (hiveMetastoreSiteURL != null) {
      conf.addResource(hiveMetastoreSiteURL);
    }

    // Add in our conf file
    metastoreSiteURL = findConfigFile(classLoader, "metastore-site.xml");
    if (metastoreSiteURL != null) {
      conf.addResource(metastoreSiteURL);
    }

    // If a system property that matches one of our conf value names is set then use the value
    // it's set to to set our own conf value.
    for (ConfVars var : ConfVars.values()) {
      if (System.getProperty(var.varname) != null) {
        LOG.debug(
            "Setting conf value "
                + var.varname
                + " using value "
                + System.getProperty(var.varname));
        conf.set(var.varname, System.getProperty(var.varname));
      }
    }

    // Pick up any system properties that start with "hive." and set them in our config.  This
    // way we can properly pull any Hive values from the environment without needing to know all
    // of the Hive config values.
    System.getProperties().stringPropertyNames().stream()
        .filter(s -> s.startsWith("hive."))
        .forEach(
            s -> {
              String v = System.getProperty(s);
              LOG.debug("Picking up system property " + s + " with value " + v);
              conf.set(s, v);
            });

    if (!beenDumped.getAndSet(true)
        && getBoolVar(conf, ConfVars.DUMP_CONFIG_ON_CREATION)
        && LOG.isDebugEnabled()) {
      LOG.debug(dumpConfig(conf));
    }

    /*
    Add deprecated config names to configuration.
    The parameters for Configuration.addDeprecation are (oldKey, newKey) and it is assumed that the config is set via
    newKey and the value is retrieved via oldKey.
    However in this case we assume the value is set with the deprecated key (oldKey) in some config file and we
    retrieve it in the code via the new key. So the parameter order we use here is: (newKey, deprecatedKey).
    We do this with the HiveConf configs as well.
     */
    for (ConfVars var : ConfVars.values()) {
      if (var.deprecatedName != null) {
        Configuration.addDeprecation(var.getVarname(), var.deprecatedName);
      }
      if (var.hiveDeprecatedName != null) {
        Configuration.addDeprecation(var.getHiveName(), var.hiveDeprecatedName);
      }
    }

    return conf;
  }

  private static URL findConfigFile(ClassLoader classLoader, String name) {
    // First, look in the classpath
    URL result = classLoader.getResource(name);
    if (result == null) {
      // Nope, so look to see if our conf dir has been explicitly set
      result = seeIfConfAtThisLocation("METASTORE_CONF_DIR", name, false);
    }
    if (result == null) {
      // Nope, so look to see if our home dir has been explicitly set
      result = seeIfConfAtThisLocation("METASTORE_HOME", name, true);
    }
    if (result == null) {
      // Nope, so look to see if Hive's conf dir has been explicitly set
      result = seeIfConfAtThisLocation("HIVE_CONF_DIR", name, false);
    }
    if (result == null) {
      // Nope, so look to see if Hive's home dir has been explicitly set
      result = seeIfConfAtThisLocation("HIVE_HOME", name, true);
    }
    if (result == null) {
      // Nope, so look to see if we can find a conf file by finding our jar, going up one
      // directory, and looking for a conf directory.
      URI jarUri = null;
      try {
        jarUri = MetastoreConf.class.getProtectionDomain().getCodeSource().getLocation().toURI();
      } catch (Throwable e) {
        LOG.warn("Cannot get jar URI", e);
      }
      if (jarUri != null) {
        result = seeIfConfAtThisLocation(new File(jarUri).getParent(), name, true);
      }
    }

    if (result == null) {
      LOG.info("Unable to find config file: " + name);
    } else {
      LOG.info("Found configuration file: " + result);
    }

    return result;
  }

  private static URL seeIfConfAtThisLocation(String envVar, String name, boolean inConfDir) {
    String path = System.getenv(envVar);
    if (path == null) {
      // Workaround for testing since tests can't set the env vars.
      path = System.getProperty(TEST_ENV_WORKAROUND + envVar);
    }
    if (path != null) {
      String suffix = inConfDir ? "conf" + File.separatorChar + name : name;
      return checkConfigFile(new File(path, suffix));
    }
    return null;
  }

  private static URL checkConfigFile(File f) {
    try {
      return (f.exists() && f.isFile()) ? f.toURI().toURL() : null;
    } catch (Throwable e) {
      LOG.warn("Error looking for config " + f, e);
      return null;
    }
  }

  // In all of the getters, we try the metastore value name first.  If it is not set we try the
  // Hive value name.

  /**
   * Get the variable as a string
   *
   * @param conf configuration to retrieve it from
   * @param var variable to retrieve
   * @return value, or default value if value not in config file
   */
  public static String getVar(Configuration conf, ConfVars var) {
    assert var.defaultVal.getClass() == String.class;
    String val = conf.get(var.varname);
    return val == null ? conf.get(var.hiveName, (String) var.defaultVal) : val;
  }

  /**
   * Get the variable as a string
   *
   * @param conf configuration to retrieve it from
   * @param var variable to retrieve
   * @param defaultVal default to return if the variable is unset
   * @return value, or default value passed in if the value is not in the config file
   */
  public static String getVar(Configuration conf, ConfVars var, String defaultVal) {
    assert var.defaultVal.getClass() == String.class;
    String val = conf.get(var.varname);
    return val == null ? conf.get(var.hiveName, defaultVal) : val;
  }

  /**
   * Treat a configuration value as a comma separated list.
   *
   * @param conf configuration to retrieve it from
   * @param var variable to retrieve
   * @return collection of strings. If the value is unset it will return an empty collection.
   */
  public static Collection<String> getStringCollection(Configuration conf, ConfVars var) {
    assert var.defaultVal.getClass() == String.class;
    String val = conf.get(var.varname);
    if (val == null) {
      val = conf.get(var.hiveName, (String) var.defaultVal);
    }
    if (val == null) {
      return Collections.emptySet();
    }
    return StringUtils.asSet(val.split(","));
  }

  /**
   * Set the variable as a string
   *
   * @param conf configuration file to set it in
   * @param var variable to set
   * @param val value to set it to
   */
  public static void setVar(Configuration conf, ConfVars var, String val) {
    assert var.defaultVal.getClass() == String.class;
    conf.set(var.varname, val);
  }

  /**
   * Get the variable as a int. Note that all integer valued variables are stored as longs, thus
   * this downcasts from a long to an in.
   *
   * @param conf configuration to retrieve it from
   * @param var variable to retrieve
   * @return value, or default value if value not in config file
   */
  public static int getIntVar(Configuration conf, ConfVars var) {
    long val = getLongVar(conf, var);
    assert val <= Integer.MAX_VALUE;
    return (int) val;
  }

  /**
   * Get the variable as a long
   *
   * @param conf configuration to retrieve it from
   * @param var variable to retrieve
   * @return value, or default value if value not in config file
   */
  public static long getLongVar(Configuration conf, ConfVars var) {
    assert var.defaultVal.getClass() == Long.class;
    String val = conf.get(var.varname);
    return val == null ? conf.getLong(var.hiveName, (Long) var.defaultVal) : Long.parseLong(val);
  }

  /**
   * Set the variable as a long
   *
   * @param conf configuration file to set it in
   * @param var variable to set
   * @param val value to set it to
   */
  public static void setLongVar(Configuration conf, ConfVars var, long val) {
    assert var.defaultVal.getClass() == Long.class;
    conf.setLong(var.varname, val);
  }

  /**
   * Get the variable as a boolean
   *
   * @param conf configuration to retrieve it from
   * @param var variable to retrieve
   * @return value, or default value if value not in config file
   */
  public static boolean getBoolVar(Configuration conf, ConfVars var) {
    assert var.defaultVal.getClass() == Boolean.class;
    String val = conf.get(var.varname);
    return val == null
        ? conf.getBoolean(var.hiveName, (Boolean) var.defaultVal)
        : Boolean.valueOf(val);
  }

  /**
   * Get values from comma-separated config, to an array after extracting individual values.
   *
   * @param conf Configuration to retrieve it from
   * @param var variable to retrieve
   * @return Array of String, containing each value from the comma-separated config, or default
   *     value if value not in config file
   */
  public static String[] getTrimmedStringsVar(Configuration conf, ConfVars var) {
    assert var.defaultVal.getClass() == String.class;
    String[] result = conf.getTrimmedStrings(var.varname, (String[]) null);
    if (result != null) {
      return result;
    }
    if (var.hiveName != null) {
      result = conf.getTrimmedStrings(var.hiveName, (String[]) null);
      if (result != null) {
        return result;
      }
    }
    return org.apache.hadoop.util.StringUtils.getTrimmedStrings((String) var.getDefaultVal());
  }

  /**
   * Set the variable as a boolean
   *
   * @param conf configuration file to set it in
   * @param var variable to set
   * @param val value to set it to
   */
  public static void setBoolVar(Configuration conf, ConfVars var, boolean val) {
    assert var.defaultVal.getClass() == Boolean.class;
    conf.setBoolean(var.varname, val);
  }

  /**
   * Get the variable as a double
   *
   * @param conf configuration to retrieve it from
   * @param var variable to retrieve
   * @return value, or default value if value not in config file
   */
  public static double getDoubleVar(Configuration conf, ConfVars var) {
    assert var.defaultVal.getClass() == Double.class;
    String val = conf.get(var.varname);
    return val == null
        ? conf.getDouble(var.hiveName, (Double) var.defaultVal)
        : Double.valueOf(val);
  }

  /**
   * Set the variable as a double
   *
   * @param conf configuration file to set it in
   * @param var variable to set
   * @param val value to set it to
   */
  public static void setDoubleVar(Configuration conf, ConfVars var, double val) {
    assert var.defaultVal.getClass() == Double.class;
    conf.setDouble(var.varname, val);
  }

  public static long getSizeVar(Configuration conf, ConfVars var) {
    return SizeValidator.toSizeBytes(getVar(conf, var));
  }

  /**
   * Get a class instance based on a configuration value
   *
   * @param conf configuration file to retrieve it from
   * @param var variable to retrieve
   * @param defaultValue default class to return if the value isn't set
   * @param xface interface that class must implement
   * @param <I> interface that class implements
   * @return instance of the class
   */
  public static <I> Class<? extends I> getClass(
      Configuration conf, ConfVars var, Class<? extends I> defaultValue, Class<I> xface) {
    assert var.defaultVal.getClass() == String.class;
    String val = conf.get(var.varname);
    return val == null
        ? conf.getClass(var.hiveName, defaultValue, xface)
        : conf.getClass(var.varname, defaultValue, xface);
  }

  /**
   * Set the class name in the configuration file
   *
   * @param conf configuration file to set it in
   * @param var variable to set
   * @param theClass the class to set it to
   * @param xface interface that the class implements. I don't know why this is required, but the
   *     underlying {@link Configuration#setClass(String, Class, Class)} requires it.
   * @param <I> interface the class implements.
   */
  public static <I> void setClass(
      Configuration conf, ConfVars var, Class<? extends I> theClass, Class<I> xface) {
    assert var.defaultVal.getClass() == String.class;
    conf.setClass(var.varname, theClass, xface);
  }

  /**
   * Get the variable as a long indicating a period of time
   *
   * @param conf configuration to retrieve it from
   * @param var variable to retrieve
   * @param outUnit Timeout to return value in
   * @return value, or default value if value not in config file
   */
  public static long getTimeVar(Configuration conf, ConfVars var, TimeUnit outUnit) {
    assert var.defaultVal.getClass() == TimeValue.class;
    String val = conf.get(var.varname);

    if (val == null) {
      // Look for it under the old Hive name
      val = conf.get(var.hiveName);
    }

    if (val != null) {
      return convertTimeStr(val, ((TimeValue) var.defaultVal).unit, outUnit);
    } else {
      return outUnit.convert(((TimeValue) var.defaultVal).val, ((TimeValue) var.defaultVal).unit);
    }
  }

  /**
   * Set the variable as a string
   *
   * @param conf configuration file to set it in
   * @param var variable to set
   * @param duration value to set it to
   * @param unit time unit that duration is expressed in
   */
  public static void setTimeVar(Configuration conf, ConfVars var, long duration, TimeUnit unit) {
    assert var.defaultVal.getClass() == TimeValue.class;
    conf.setTimeDuration(var.varname, duration, unit);
  }

  public static long convertTimeStr(String val, TimeUnit defaultUnit, TimeUnit outUnit) {
    if (val.charAt(val.length() - 1) >= 'A') {
      // It ends in a character, this means they appended a time indicator (e.g. 600s)
      Matcher m = TIME_UNIT_SUFFIX.matcher(val);
      if (m.matches()) {
        long duration = Long.parseLong(m.group(1));
        String unit = m.group(2).toLowerCase();

        // If/else chain arranged in likely order of frequency for performance
        if (unit.equals("s") || unit.startsWith("sec")) {
          return outUnit.convert(duration, TimeUnit.SECONDS);
        } else if (unit.equals("ms") || unit.startsWith("msec")) {
          return outUnit.convert(duration, TimeUnit.MILLISECONDS);
        } else if (unit.equals("m") || unit.startsWith("min")) {
          return outUnit.convert(duration, TimeUnit.MINUTES);
        } else if (unit.equals("us") || unit.startsWith("usec")) {
          return outUnit.convert(duration, TimeUnit.MICROSECONDS);
        } else if (unit.equals("ns") || unit.startsWith("nsec")) {
          return outUnit.convert(duration, TimeUnit.NANOSECONDS);
        } else if (unit.equals("h") || unit.startsWith("hour")) {
          return outUnit.convert(duration, TimeUnit.HOURS);
        } else if (unit.equals("d") || unit.startsWith("day")) {
          return outUnit.convert(duration, TimeUnit.DAYS);
        } else {
          throw new IllegalArgumentException("Invalid time unit " + unit);
        }
      } else {
        throw new IllegalArgumentException("Invalid time unit " + val);
      }
    }

    // If they gave a value but not a time unit assume the default time unit.
    return outUnit.convert(Long.parseLong(val), defaultUnit);
  }

  static String timeAbbreviationFor(TimeUnit timeunit) {
    switch (timeunit) {
      case DAYS:
        return "d";
      case HOURS:
        return "h";
      case MINUTES:
        return "m";
      case SECONDS:
        return "s";
      case MILLISECONDS:
        return "ms";
      case MICROSECONDS:
        return "us";
      case NANOSECONDS:
        return "ns";
    }
    throw new IllegalArgumentException("Invalid timeunit " + timeunit);
  }

  /**
   * Get a password from the configuration file. This uses Hadoop's {@link
   * Configuration#getPassword(String)} to handle getting secure passwords.
   *
   * @param conf configuration file to read from
   * @param var configuration value to read
   * @return the password as a string, or the default value.
   * @throws IOException if thrown by Configuration.getPassword
   */
  public static String getPassword(Configuration conf, ConfVars var) throws IOException {
    assert var.defaultVal.getClass() == String.class;
    char[] pw = conf.getPassword(var.varname);
    if (pw == null) {
      // Might be under the hive name
      pw = conf.getPassword(var.hiveName);
    }
    return pw == null ? var.defaultVal.toString() : new String(pw);
  }

  /**
   * Get the configuration value based on a string rather than a ConfVar. This will do the mapping
   * between metastore keys and Hive keys. That is, if there's a ConfVar with a metastore key of
   * "metastore.a" and a hive key of "hive.a", the value for that variable will be returned if
   * either of those keys is present in the config. If neither are present than the default value
   * will be returned.
   *
   * @param conf configuration to read.
   * @param key metastore or hive key to read.
   * @return the value set
   */
  public static String get(Configuration conf, String key) {
    ConfVars var = keyToVars.get(key);
    if (var == null) {
      // Ok, this isn't one we track.  Just return whatever matches the string
      return conf.get(key);
    }
    // Check if the metastore key is set first
    String val = conf.get(var.varname);
    return val == null ? conf.get(var.hiveName, var.defaultVal.toString()) : val;
  }

  public static boolean isPrintable(String key) {
    return !unprintables.contains(key);
  }

  /**
   * Return the configuration value as a String. For time based values it will be returned in the
   * default time unit appended with an appropriate abbreviation (eg s for seconds, ...)
   *
   * @param conf configuration to read
   * @param var variable to read
   * @return value as a String
   */
  public static String getAsString(Configuration conf, ConfVars var) {
    if (var.defaultVal.getClass() == String.class) {
      return getVar(conf, var);
    } else if (var.defaultVal.getClass() == Boolean.class) {
      return Boolean.toString(getBoolVar(conf, var));
    } else if (var.defaultVal.getClass() == Long.class) {
      return Long.toString(getLongVar(conf, var));
    } else if (var.defaultVal.getClass() == Double.class) {
      return Double.toString(getDoubleVar(conf, var));
    } else if (var.defaultVal.getClass() == TimeValue.class) {
      TimeUnit timeUnit = ((TimeValue) var.defaultVal).unit;
      return getTimeVar(conf, var, timeUnit) + timeAbbreviationFor(timeUnit);
    } else {
      throw new RuntimeException(
          "Unknown type for getObject " + var.defaultVal.getClass().getName());
    }
  }

  public static URL getHiveDefaultLocation() {
    return hiveDefaultURL;
  }

  public static URL getHiveSiteLocation() {
    return hiveSiteURL;
  }

  public static URL getHiveMetastoreSiteURL() {
    return hiveMetastoreSiteURL;
  }

  public static URL getMetastoreSiteURL() {
    return metastoreSiteURL;
  }

  public List<URL> getResourceFileLocations() {
    return Arrays.asList(hiveSiteURL, hiveMetastoreSiteURL, metastoreSiteURL);
  }

  /**
   * Check if metastore is being used in embedded mode. This utility function exists so that the
   * logic for determining the mode is same in HiveConf and HiveMetaStoreClient
   *
   * @param msUri - metastore server uri
   * @return true if the metastore is embedded
   */
  public static boolean isEmbeddedMetaStore(String msUri) {
    return (msUri == null) || msUri.trim().isEmpty();
  }

  public static ZooKeeperHiveHelper getZKConfig(Configuration conf) {
    return ZooKeeperHiveHelper.builder()
        .quorum(MetastoreConf.getVar(conf, ConfVars.THRIFT_URIS))
        .clientPort(MetastoreConf.getVar(conf, ConfVars.THRIFT_ZOOKEEPER_CLIENT_PORT))
        .serverRegistryNameSpace(MetastoreConf.getVar(conf, ConfVars.THRIFT_ZOOKEEPER_NAMESPACE))
        .connectionTimeout(
            (int)
                getTimeVar(
                    conf, ConfVars.THRIFT_ZOOKEEPER_CONNECTION_TIMEOUT, TimeUnit.MILLISECONDS))
        .sessionTimeout(
            (int)
                MetastoreConf.getTimeVar(
                    conf, ConfVars.THRIFT_ZOOKEEPER_SESSION_TIMEOUT, TimeUnit.MILLISECONDS))
        .baseSleepTime(
            (int)
                MetastoreConf.getTimeVar(
                    conf,
                    ConfVars.THRIFT_ZOOKEEPER_CONNECTION_BASESLEEPTIME,
                    TimeUnit.MILLISECONDS))
        .maxRetries(MetastoreConf.getIntVar(conf, ConfVars.THRIFT_ZOOKEEPER_CONNECTION_MAX_RETRIES))
        .build();
  }

  /**
   * Dump the configuration file to the log. It will be dumped at an INFO level. This can
   * potentially produce a lot of logs, so you might want to be careful when and where you do it. It
   * takes care not to dump hidden keys.
   *
   * @param conf Configuration file to dump
   * @return String containing dumped config file.
   */
  static String dumpConfig(Configuration conf) {
    StringBuilder buf = new StringBuilder("MetastoreConf object:\n");
    if (hiveSiteURL != null) {
      buf.append("Used hive-site file: ").append(hiveSiteURL).append('\n');
    }
    if (hiveMetastoreSiteURL != null) {
      buf.append("Used hivemetastore-site file: ").append(hiveMetastoreSiteURL).append('\n');
    }
    if (metastoreSiteURL != null) {
      buf.append("Used metastore-site file: ").append(metastoreSiteURL).append('\n');
    }
    for (ConfVars var : ConfVars.values()) {
      if (!unprintables.contains(var.varname)) {
        buf.append("Key: <")
            .append(var.varname)
            .append("> old hive key: <")
            .append(var.hiveName)
            .append(">  value: <")
            .append(getAsString(conf, var))
            .append(">\n");
      }
    }
    buf.append("Finished MetastoreConf object.\n");
    return buf.toString();
  }

  public static char[] getValueFromKeystore(String keystorePath, String key) throws IOException {
    char[] valueCharArray = null;
    if (keystorePath != null && key != null) {
      Configuration conf = new Configuration();
      conf.set(CredentialProviderFactory.CREDENTIAL_PROVIDER_PATH, keystorePath);
      valueCharArray = conf.getPassword(key);
    }
    return valueCharArray;
  }
}
