/**
 * Autogenerated by Thrift Compiler (0.16.0)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
package org.apache.hadoop.hive.metastore.api;

@SuppressWarnings({"cast", "rawtypes", "serial", "unchecked", "unused"})
@javax.annotation.Generated(value = "Autogenerated by Thrift Compiler (0.16.0)")
@org.apache.hadoop.classification.InterfaceAudience.Public @org.apache.hadoop.classification.InterfaceStability.Stable public class WMNullableResourcePlan implements org.apache.thrift.TBase<WMNullableResourcePlan, WMNullableResourcePlan._Fields>, java.io.Serializable, Cloneable, Comparable<WMNullableResourcePlan> {
  private static final org.apache.thrift.protocol.TStruct STRUCT_DESC = new org.apache.thrift.protocol.TStruct("WMNullableResourcePlan");

  private static final org.apache.thrift.protocol.TField NAME_FIELD_DESC = new org.apache.thrift.protocol.TField("name", org.apache.thrift.protocol.TType.STRING, (short)1);
  private static final org.apache.thrift.protocol.TField STATUS_FIELD_DESC = new org.apache.thrift.protocol.TField("status", org.apache.thrift.protocol.TType.I32, (short)2);
  private static final org.apache.thrift.protocol.TField QUERY_PARALLELISM_FIELD_DESC = new org.apache.thrift.protocol.TField("queryParallelism", org.apache.thrift.protocol.TType.I32, (short)4);
  private static final org.apache.thrift.protocol.TField IS_SET_QUERY_PARALLELISM_FIELD_DESC = new org.apache.thrift.protocol.TField("isSetQueryParallelism", org.apache.thrift.protocol.TType.BOOL, (short)5);
  private static final org.apache.thrift.protocol.TField DEFAULT_POOL_PATH_FIELD_DESC = new org.apache.thrift.protocol.TField("defaultPoolPath", org.apache.thrift.protocol.TType.STRING, (short)6);
  private static final org.apache.thrift.protocol.TField IS_SET_DEFAULT_POOL_PATH_FIELD_DESC = new org.apache.thrift.protocol.TField("isSetDefaultPoolPath", org.apache.thrift.protocol.TType.BOOL, (short)7);
  private static final org.apache.thrift.protocol.TField NS_FIELD_DESC = new org.apache.thrift.protocol.TField("ns", org.apache.thrift.protocol.TType.STRING, (short)8);

  private static final org.apache.thrift.scheme.SchemeFactory STANDARD_SCHEME_FACTORY = new WMNullableResourcePlanStandardSchemeFactory();
  private static final org.apache.thrift.scheme.SchemeFactory TUPLE_SCHEME_FACTORY = new WMNullableResourcePlanTupleSchemeFactory();

  private @org.apache.thrift.annotation.Nullable java.lang.String name; // optional
  private @org.apache.thrift.annotation.Nullable WMResourcePlanStatus status; // optional
  private int queryParallelism; // optional
  private boolean isSetQueryParallelism; // optional
  private @org.apache.thrift.annotation.Nullable java.lang.String defaultPoolPath; // optional
  private boolean isSetDefaultPoolPath; // optional
  private @org.apache.thrift.annotation.Nullable java.lang.String ns; // optional

  /** The set of fields this struct contains, along with convenience methods for finding and manipulating them. */
  public enum _Fields implements org.apache.thrift.TFieldIdEnum {
    NAME((short)1, "name"),
    /**
     * 
     * @see WMResourcePlanStatus
     */
    STATUS((short)2, "status"),
    QUERY_PARALLELISM((short)4, "queryParallelism"),
    IS_SET_QUERY_PARALLELISM((short)5, "isSetQueryParallelism"),
    DEFAULT_POOL_PATH((short)6, "defaultPoolPath"),
    IS_SET_DEFAULT_POOL_PATH((short)7, "isSetDefaultPoolPath"),
    NS((short)8, "ns");

    private static final java.util.Map<java.lang.String, _Fields> byName = new java.util.HashMap<java.lang.String, _Fields>();

    static {
      for (_Fields field : java.util.EnumSet.allOf(_Fields.class)) {
        byName.put(field.getFieldName(), field);
      }
    }

    /**
     * Find the _Fields constant that matches fieldId, or null if its not found.
     */
    @org.apache.thrift.annotation.Nullable
    public static _Fields findByThriftId(int fieldId) {
      switch(fieldId) {
        case 1: // NAME
          return NAME;
        case 2: // STATUS
          return STATUS;
        case 4: // QUERY_PARALLELISM
          return QUERY_PARALLELISM;
        case 5: // IS_SET_QUERY_PARALLELISM
          return IS_SET_QUERY_PARALLELISM;
        case 6: // DEFAULT_POOL_PATH
          return DEFAULT_POOL_PATH;
        case 7: // IS_SET_DEFAULT_POOL_PATH
          return IS_SET_DEFAULT_POOL_PATH;
        case 8: // NS
          return NS;
        default:
          return null;
      }
    }

    /**
     * Find the _Fields constant that matches fieldId, throwing an exception
     * if it is not found.
     */
    public static _Fields findByThriftIdOrThrow(int fieldId) {
      _Fields fields = findByThriftId(fieldId);
      if (fields == null) throw new java.lang.IllegalArgumentException("Field " + fieldId + " doesn't exist!");
      return fields;
    }

    /**
     * Find the _Fields constant that matches name, or null if its not found.
     */
    @org.apache.thrift.annotation.Nullable
    public static _Fields findByName(java.lang.String name) {
      return byName.get(name);
    }

    private final short _thriftId;
    private final java.lang.String _fieldName;

    _Fields(short thriftId, java.lang.String fieldName) {
      _thriftId = thriftId;
      _fieldName = fieldName;
    }

    public short getThriftFieldId() {
      return _thriftId;
    }

    public java.lang.String getFieldName() {
      return _fieldName;
    }
  }

  // isset id assignments
  private static final int __QUERYPARALLELISM_ISSET_ID = 0;
  private static final int __ISSETQUERYPARALLELISM_ISSET_ID = 1;
  private static final int __ISSETDEFAULTPOOLPATH_ISSET_ID = 2;
  private byte __isset_bitfield = 0;
  private static final _Fields optionals[] = {_Fields.NAME,_Fields.STATUS,_Fields.QUERY_PARALLELISM,_Fields.IS_SET_QUERY_PARALLELISM,_Fields.DEFAULT_POOL_PATH,_Fields.IS_SET_DEFAULT_POOL_PATH,_Fields.NS};
  public static final java.util.Map<_Fields, org.apache.thrift.meta_data.FieldMetaData> metaDataMap;
  static {
    java.util.Map<_Fields, org.apache.thrift.meta_data.FieldMetaData> tmpMap = new java.util.EnumMap<_Fields, org.apache.thrift.meta_data.FieldMetaData>(_Fields.class);
    tmpMap.put(_Fields.NAME, new org.apache.thrift.meta_data.FieldMetaData("name", org.apache.thrift.TFieldRequirementType.OPTIONAL, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.STRING)));
    tmpMap.put(_Fields.STATUS, new org.apache.thrift.meta_data.FieldMetaData("status", org.apache.thrift.TFieldRequirementType.OPTIONAL, 
        new org.apache.thrift.meta_data.EnumMetaData(org.apache.thrift.protocol.TType.ENUM, WMResourcePlanStatus.class)));
    tmpMap.put(_Fields.QUERY_PARALLELISM, new org.apache.thrift.meta_data.FieldMetaData("queryParallelism", org.apache.thrift.TFieldRequirementType.OPTIONAL, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.I32)));
    tmpMap.put(_Fields.IS_SET_QUERY_PARALLELISM, new org.apache.thrift.meta_data.FieldMetaData("isSetQueryParallelism", org.apache.thrift.TFieldRequirementType.OPTIONAL, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.BOOL)));
    tmpMap.put(_Fields.DEFAULT_POOL_PATH, new org.apache.thrift.meta_data.FieldMetaData("defaultPoolPath", org.apache.thrift.TFieldRequirementType.OPTIONAL, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.STRING)));
    tmpMap.put(_Fields.IS_SET_DEFAULT_POOL_PATH, new org.apache.thrift.meta_data.FieldMetaData("isSetDefaultPoolPath", org.apache.thrift.TFieldRequirementType.OPTIONAL, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.BOOL)));
    tmpMap.put(_Fields.NS, new org.apache.thrift.meta_data.FieldMetaData("ns", org.apache.thrift.TFieldRequirementType.OPTIONAL, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.STRING)));
    metaDataMap = java.util.Collections.unmodifiableMap(tmpMap);
    org.apache.thrift.meta_data.FieldMetaData.addStructMetaDataMap(WMNullableResourcePlan.class, metaDataMap);
  }

  public WMNullableResourcePlan() {
  }

  /**
   * Performs a deep copy on <i>other</i>.
   */
  public WMNullableResourcePlan(WMNullableResourcePlan other) {
    __isset_bitfield = other.__isset_bitfield;
    if (other.isSetName()) {
      this.name = other.name;
    }
    if (other.isSetStatus()) {
      this.status = other.status;
    }
    this.queryParallelism = other.queryParallelism;
    this.isSetQueryParallelism = other.isSetQueryParallelism;
    if (other.isSetDefaultPoolPath()) {
      this.defaultPoolPath = other.defaultPoolPath;
    }
    this.isSetDefaultPoolPath = other.isSetDefaultPoolPath;
    if (other.isSetNs()) {
      this.ns = other.ns;
    }
  }

  public WMNullableResourcePlan deepCopy() {
    return new WMNullableResourcePlan(this);
  }

  @Override
  public void clear() {
    this.name = null;
    this.status = null;
    setQueryParallelismIsSet(false);
    this.queryParallelism = 0;
    setIsSetQueryParallelismIsSet(false);
    this.isSetQueryParallelism = false;
    this.defaultPoolPath = null;
    setIsSetDefaultPoolPathIsSet(false);
    this.isSetDefaultPoolPath = false;
    this.ns = null;
  }

  @org.apache.thrift.annotation.Nullable
  public java.lang.String getName() {
    return this.name;
  }

  public void setName(@org.apache.thrift.annotation.Nullable java.lang.String name) {
    this.name = name;
  }

  public void unsetName() {
    this.name = null;
  }

  /** Returns true if field name is set (has been assigned a value) and false otherwise */
  public boolean isSetName() {
    return this.name != null;
  }

  public void setNameIsSet(boolean value) {
    if (!value) {
      this.name = null;
    }
  }

  /**
   * 
   * @see WMResourcePlanStatus
   */
  @org.apache.thrift.annotation.Nullable
  public WMResourcePlanStatus getStatus() {
    return this.status;
  }

  /**
   * 
   * @see WMResourcePlanStatus
   */
  public void setStatus(@org.apache.thrift.annotation.Nullable WMResourcePlanStatus status) {
    this.status = status;
  }

  public void unsetStatus() {
    this.status = null;
  }

  /** Returns true if field status is set (has been assigned a value) and false otherwise */
  public boolean isSetStatus() {
    return this.status != null;
  }

  public void setStatusIsSet(boolean value) {
    if (!value) {
      this.status = null;
    }
  }

  public int getQueryParallelism() {
    return this.queryParallelism;
  }

  public void setQueryParallelism(int queryParallelism) {
    this.queryParallelism = queryParallelism;
    setQueryParallelismIsSet(true);
  }

  public void unsetQueryParallelism() {
    __isset_bitfield = org.apache.thrift.EncodingUtils.clearBit(__isset_bitfield, __QUERYPARALLELISM_ISSET_ID);
  }

  /** Returns true if field queryParallelism is set (has been assigned a value) and false otherwise */
  public boolean isSetQueryParallelism() {
    return org.apache.thrift.EncodingUtils.testBit(__isset_bitfield, __QUERYPARALLELISM_ISSET_ID);
  }

  public void setQueryParallelismIsSet(boolean value) {
    __isset_bitfield = org.apache.thrift.EncodingUtils.setBit(__isset_bitfield, __QUERYPARALLELISM_ISSET_ID, value);
  }

  public boolean isIsSetQueryParallelism() {
    return this.isSetQueryParallelism;
  }

  public void setIsSetQueryParallelism(boolean isSetQueryParallelism) {
    this.isSetQueryParallelism = isSetQueryParallelism;
    setIsSetQueryParallelismIsSet(true);
  }

  public void unsetIsSetQueryParallelism() {
    __isset_bitfield = org.apache.thrift.EncodingUtils.clearBit(__isset_bitfield, __ISSETQUERYPARALLELISM_ISSET_ID);
  }

  /** Returns true if field isSetQueryParallelism is set (has been assigned a value) and false otherwise */
  public boolean isSetIsSetQueryParallelism() {
    return org.apache.thrift.EncodingUtils.testBit(__isset_bitfield, __ISSETQUERYPARALLELISM_ISSET_ID);
  }

  public void setIsSetQueryParallelismIsSet(boolean value) {
    __isset_bitfield = org.apache.thrift.EncodingUtils.setBit(__isset_bitfield, __ISSETQUERYPARALLELISM_ISSET_ID, value);
  }

  @org.apache.thrift.annotation.Nullable
  public java.lang.String getDefaultPoolPath() {
    return this.defaultPoolPath;
  }

  public void setDefaultPoolPath(@org.apache.thrift.annotation.Nullable java.lang.String defaultPoolPath) {
    this.defaultPoolPath = defaultPoolPath;
  }

  public void unsetDefaultPoolPath() {
    this.defaultPoolPath = null;
  }

  /** Returns true if field defaultPoolPath is set (has been assigned a value) and false otherwise */
  public boolean isSetDefaultPoolPath() {
    return this.defaultPoolPath != null;
  }

  public void setDefaultPoolPathIsSet(boolean value) {
    if (!value) {
      this.defaultPoolPath = null;
    }
  }

  public boolean isIsSetDefaultPoolPath() {
    return this.isSetDefaultPoolPath;
  }

  public void setIsSetDefaultPoolPath(boolean isSetDefaultPoolPath) {
    this.isSetDefaultPoolPath = isSetDefaultPoolPath;
    setIsSetDefaultPoolPathIsSet(true);
  }

  public void unsetIsSetDefaultPoolPath() {
    __isset_bitfield = org.apache.thrift.EncodingUtils.clearBit(__isset_bitfield, __ISSETDEFAULTPOOLPATH_ISSET_ID);
  }

  /** Returns true if field isSetDefaultPoolPath is set (has been assigned a value) and false otherwise */
  public boolean isSetIsSetDefaultPoolPath() {
    return org.apache.thrift.EncodingUtils.testBit(__isset_bitfield, __ISSETDEFAULTPOOLPATH_ISSET_ID);
  }

  public void setIsSetDefaultPoolPathIsSet(boolean value) {
    __isset_bitfield = org.apache.thrift.EncodingUtils.setBit(__isset_bitfield, __ISSETDEFAULTPOOLPATH_ISSET_ID, value);
  }

  @org.apache.thrift.annotation.Nullable
  public java.lang.String getNs() {
    return this.ns;
  }

  public void setNs(@org.apache.thrift.annotation.Nullable java.lang.String ns) {
    this.ns = ns;
  }

  public void unsetNs() {
    this.ns = null;
  }

  /** Returns true if field ns is set (has been assigned a value) and false otherwise */
  public boolean isSetNs() {
    return this.ns != null;
  }

  public void setNsIsSet(boolean value) {
    if (!value) {
      this.ns = null;
    }
  }

  public void setFieldValue(_Fields field, @org.apache.thrift.annotation.Nullable java.lang.Object value) {
    switch (field) {
    case NAME:
      if (value == null) {
        unsetName();
      } else {
        setName((java.lang.String)value);
      }
      break;

    case STATUS:
      if (value == null) {
        unsetStatus();
      } else {
        setStatus((WMResourcePlanStatus)value);
      }
      break;

    case QUERY_PARALLELISM:
      if (value == null) {
        unsetQueryParallelism();
      } else {
        setQueryParallelism((java.lang.Integer)value);
      }
      break;

    case IS_SET_QUERY_PARALLELISM:
      if (value == null) {
        unsetIsSetQueryParallelism();
      } else {
        setIsSetQueryParallelism((java.lang.Boolean)value);
      }
      break;

    case DEFAULT_POOL_PATH:
      if (value == null) {
        unsetDefaultPoolPath();
      } else {
        setDefaultPoolPath((java.lang.String)value);
      }
      break;

    case IS_SET_DEFAULT_POOL_PATH:
      if (value == null) {
        unsetIsSetDefaultPoolPath();
      } else {
        setIsSetDefaultPoolPath((java.lang.Boolean)value);
      }
      break;

    case NS:
      if (value == null) {
        unsetNs();
      } else {
        setNs((java.lang.String)value);
      }
      break;

    }
  }

  @org.apache.thrift.annotation.Nullable
  public java.lang.Object getFieldValue(_Fields field) {
    switch (field) {
    case NAME:
      return getName();

    case STATUS:
      return getStatus();

    case QUERY_PARALLELISM:
      return getQueryParallelism();

    case IS_SET_QUERY_PARALLELISM:
      return isIsSetQueryParallelism();

    case DEFAULT_POOL_PATH:
      return getDefaultPoolPath();

    case IS_SET_DEFAULT_POOL_PATH:
      return isIsSetDefaultPoolPath();

    case NS:
      return getNs();

    }
    throw new java.lang.IllegalStateException();
  }

  /** Returns true if field corresponding to fieldID is set (has been assigned a value) and false otherwise */
  public boolean isSet(_Fields field) {
    if (field == null) {
      throw new java.lang.IllegalArgumentException();
    }

    switch (field) {
    case NAME:
      return isSetName();
    case STATUS:
      return isSetStatus();
    case QUERY_PARALLELISM:
      return isSetQueryParallelism();
    case IS_SET_QUERY_PARALLELISM:
      return isSetIsSetQueryParallelism();
    case DEFAULT_POOL_PATH:
      return isSetDefaultPoolPath();
    case IS_SET_DEFAULT_POOL_PATH:
      return isSetIsSetDefaultPoolPath();
    case NS:
      return isSetNs();
    }
    throw new java.lang.IllegalStateException();
  }

  @Override
  public boolean equals(java.lang.Object that) {
    if (that instanceof WMNullableResourcePlan)
      return this.equals((WMNullableResourcePlan)that);
    return false;
  }

  public boolean equals(WMNullableResourcePlan that) {
    if (that == null)
      return false;
    if (this == that)
      return true;

    boolean this_present_name = true && this.isSetName();
    boolean that_present_name = true && that.isSetName();
    if (this_present_name || that_present_name) {
      if (!(this_present_name && that_present_name))
        return false;
      if (!this.name.equals(that.name))
        return false;
    }

    boolean this_present_status = true && this.isSetStatus();
    boolean that_present_status = true && that.isSetStatus();
    if (this_present_status || that_present_status) {
      if (!(this_present_status && that_present_status))
        return false;
      if (!this.status.equals(that.status))
        return false;
    }

    boolean this_present_queryParallelism = true && this.isSetQueryParallelism();
    boolean that_present_queryParallelism = true && that.isSetQueryParallelism();
    if (this_present_queryParallelism || that_present_queryParallelism) {
      if (!(this_present_queryParallelism && that_present_queryParallelism))
        return false;
      if (this.queryParallelism != that.queryParallelism)
        return false;
    }

    boolean this_present_isSetQueryParallelism = true && this.isSetIsSetQueryParallelism();
    boolean that_present_isSetQueryParallelism = true && that.isSetIsSetQueryParallelism();
    if (this_present_isSetQueryParallelism || that_present_isSetQueryParallelism) {
      if (!(this_present_isSetQueryParallelism && that_present_isSetQueryParallelism))
        return false;
      if (this.isSetQueryParallelism != that.isSetQueryParallelism)
        return false;
    }

    boolean this_present_defaultPoolPath = true && this.isSetDefaultPoolPath();
    boolean that_present_defaultPoolPath = true && that.isSetDefaultPoolPath();
    if (this_present_defaultPoolPath || that_present_defaultPoolPath) {
      if (!(this_present_defaultPoolPath && that_present_defaultPoolPath))
        return false;
      if (!this.defaultPoolPath.equals(that.defaultPoolPath))
        return false;
    }

    boolean this_present_isSetDefaultPoolPath = true && this.isSetIsSetDefaultPoolPath();
    boolean that_present_isSetDefaultPoolPath = true && that.isSetIsSetDefaultPoolPath();
    if (this_present_isSetDefaultPoolPath || that_present_isSetDefaultPoolPath) {
      if (!(this_present_isSetDefaultPoolPath && that_present_isSetDefaultPoolPath))
        return false;
      if (this.isSetDefaultPoolPath != that.isSetDefaultPoolPath)
        return false;
    }

    boolean this_present_ns = true && this.isSetNs();
    boolean that_present_ns = true && that.isSetNs();
    if (this_present_ns || that_present_ns) {
      if (!(this_present_ns && that_present_ns))
        return false;
      if (!this.ns.equals(that.ns))
        return false;
    }

    return true;
  }

  @Override
  public int hashCode() {
    int hashCode = 1;

    hashCode = hashCode * 8191 + ((isSetName()) ? 131071 : 524287);
    if (isSetName())
      hashCode = hashCode * 8191 + name.hashCode();

    hashCode = hashCode * 8191 + ((isSetStatus()) ? 131071 : 524287);
    if (isSetStatus())
      hashCode = hashCode * 8191 + status.getValue();

    hashCode = hashCode * 8191 + ((isSetQueryParallelism()) ? 131071 : 524287);
    if (isSetQueryParallelism())
      hashCode = hashCode * 8191 + queryParallelism;

    hashCode = hashCode * 8191 + ((isSetIsSetQueryParallelism()) ? 131071 : 524287);
    if (isSetIsSetQueryParallelism())
      hashCode = hashCode * 8191 + ((isSetQueryParallelism) ? 131071 : 524287);

    hashCode = hashCode * 8191 + ((isSetDefaultPoolPath()) ? 131071 : 524287);
    if (isSetDefaultPoolPath())
      hashCode = hashCode * 8191 + defaultPoolPath.hashCode();

    hashCode = hashCode * 8191 + ((isSetIsSetDefaultPoolPath()) ? 131071 : 524287);
    if (isSetIsSetDefaultPoolPath())
      hashCode = hashCode * 8191 + ((isSetDefaultPoolPath) ? 131071 : 524287);

    hashCode = hashCode * 8191 + ((isSetNs()) ? 131071 : 524287);
    if (isSetNs())
      hashCode = hashCode * 8191 + ns.hashCode();

    return hashCode;
  }

  @Override
  public int compareTo(WMNullableResourcePlan other) {
    if (!getClass().equals(other.getClass())) {
      return getClass().getName().compareTo(other.getClass().getName());
    }

    int lastComparison = 0;

    lastComparison = java.lang.Boolean.compare(isSetName(), other.isSetName());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetName()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.name, other.name);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = java.lang.Boolean.compare(isSetStatus(), other.isSetStatus());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetStatus()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.status, other.status);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = java.lang.Boolean.compare(isSetQueryParallelism(), other.isSetQueryParallelism());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetQueryParallelism()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.queryParallelism, other.queryParallelism);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = java.lang.Boolean.compare(isSetIsSetQueryParallelism(), other.isSetIsSetQueryParallelism());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetIsSetQueryParallelism()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.isSetQueryParallelism, other.isSetQueryParallelism);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = java.lang.Boolean.compare(isSetDefaultPoolPath(), other.isSetDefaultPoolPath());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetDefaultPoolPath()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.defaultPoolPath, other.defaultPoolPath);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = java.lang.Boolean.compare(isSetIsSetDefaultPoolPath(), other.isSetIsSetDefaultPoolPath());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetIsSetDefaultPoolPath()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.isSetDefaultPoolPath, other.isSetDefaultPoolPath);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = java.lang.Boolean.compare(isSetNs(), other.isSetNs());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetNs()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.ns, other.ns);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    return 0;
  }

  @org.apache.thrift.annotation.Nullable
  public _Fields fieldForId(int fieldId) {
    return _Fields.findByThriftId(fieldId);
  }

  public void read(org.apache.thrift.protocol.TProtocol iprot) throws org.apache.thrift.TException {
    scheme(iprot).read(iprot, this);
  }

  public void write(org.apache.thrift.protocol.TProtocol oprot) throws org.apache.thrift.TException {
    scheme(oprot).write(oprot, this);
  }

  @Override
  public java.lang.String toString() {
    java.lang.StringBuilder sb = new java.lang.StringBuilder("WMNullableResourcePlan(");
    boolean first = true;

    if (isSetName()) {
      sb.append("name:");
      if (this.name == null) {
        sb.append("null");
      } else {
        sb.append(this.name);
      }
      first = false;
    }
    if (isSetStatus()) {
      if (!first) sb.append(", ");
      sb.append("status:");
      if (this.status == null) {
        sb.append("null");
      } else {
        sb.append(this.status);
      }
      first = false;
    }
    if (isSetQueryParallelism()) {
      if (!first) sb.append(", ");
      sb.append("queryParallelism:");
      sb.append(this.queryParallelism);
      first = false;
    }
    if (isSetIsSetQueryParallelism()) {
      if (!first) sb.append(", ");
      sb.append("isSetQueryParallelism:");
      sb.append(this.isSetQueryParallelism);
      first = false;
    }
    if (isSetDefaultPoolPath()) {
      if (!first) sb.append(", ");
      sb.append("defaultPoolPath:");
      if (this.defaultPoolPath == null) {
        sb.append("null");
      } else {
        sb.append(this.defaultPoolPath);
      }
      first = false;
    }
    if (isSetIsSetDefaultPoolPath()) {
      if (!first) sb.append(", ");
      sb.append("isSetDefaultPoolPath:");
      sb.append(this.isSetDefaultPoolPath);
      first = false;
    }
    if (isSetNs()) {
      if (!first) sb.append(", ");
      sb.append("ns:");
      if (this.ns == null) {
        sb.append("null");
      } else {
        sb.append(this.ns);
      }
      first = false;
    }
    sb.append(")");
    return sb.toString();
  }

  public void validate() throws org.apache.thrift.TException {
    // check for required fields
    // check for sub-struct validity
  }

  private void writeObject(java.io.ObjectOutputStream out) throws java.io.IOException {
    try {
      write(new org.apache.thrift.protocol.TCompactProtocol(new org.apache.thrift.transport.TIOStreamTransport(out)));
    } catch (org.apache.thrift.TException te) {
      throw new java.io.IOException(te);
    }
  }

  private void readObject(java.io.ObjectInputStream in) throws java.io.IOException, java.lang.ClassNotFoundException {
    try {
      // it doesn't seem like you should have to do this, but java serialization is wacky, and doesn't call the default constructor.
      __isset_bitfield = 0;
      read(new org.apache.thrift.protocol.TCompactProtocol(new org.apache.thrift.transport.TIOStreamTransport(in)));
    } catch (org.apache.thrift.TException te) {
      throw new java.io.IOException(te);
    }
  }

  private static class WMNullableResourcePlanStandardSchemeFactory implements org.apache.thrift.scheme.SchemeFactory {
    public WMNullableResourcePlanStandardScheme getScheme() {
      return new WMNullableResourcePlanStandardScheme();
    }
  }

  private static class WMNullableResourcePlanStandardScheme extends org.apache.thrift.scheme.StandardScheme<WMNullableResourcePlan> {

    public void read(org.apache.thrift.protocol.TProtocol iprot, WMNullableResourcePlan struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TField schemeField;
      iprot.readStructBegin();
      while (true)
      {
        schemeField = iprot.readFieldBegin();
        if (schemeField.type == org.apache.thrift.protocol.TType.STOP) { 
          break;
        }
        switch (schemeField.id) {
          case 1: // NAME
            if (schemeField.type == org.apache.thrift.protocol.TType.STRING) {
              struct.name = iprot.readString();
              struct.setNameIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 2: // STATUS
            if (schemeField.type == org.apache.thrift.protocol.TType.I32) {
              struct.status = org.apache.hadoop.hive.metastore.api.WMResourcePlanStatus.findByValue(iprot.readI32());
              struct.setStatusIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 4: // QUERY_PARALLELISM
            if (schemeField.type == org.apache.thrift.protocol.TType.I32) {
              struct.queryParallelism = iprot.readI32();
              struct.setQueryParallelismIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 5: // IS_SET_QUERY_PARALLELISM
            if (schemeField.type == org.apache.thrift.protocol.TType.BOOL) {
              struct.isSetQueryParallelism = iprot.readBool();
              struct.setIsSetQueryParallelismIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 6: // DEFAULT_POOL_PATH
            if (schemeField.type == org.apache.thrift.protocol.TType.STRING) {
              struct.defaultPoolPath = iprot.readString();
              struct.setDefaultPoolPathIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 7: // IS_SET_DEFAULT_POOL_PATH
            if (schemeField.type == org.apache.thrift.protocol.TType.BOOL) {
              struct.isSetDefaultPoolPath = iprot.readBool();
              struct.setIsSetDefaultPoolPathIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 8: // NS
            if (schemeField.type == org.apache.thrift.protocol.TType.STRING) {
              struct.ns = iprot.readString();
              struct.setNsIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          default:
            org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
        }
        iprot.readFieldEnd();
      }
      iprot.readStructEnd();
      struct.validate();
    }

    public void write(org.apache.thrift.protocol.TProtocol oprot, WMNullableResourcePlan struct) throws org.apache.thrift.TException {
      struct.validate();

      oprot.writeStructBegin(STRUCT_DESC);
      if (struct.name != null) {
        if (struct.isSetName()) {
          oprot.writeFieldBegin(NAME_FIELD_DESC);
          oprot.writeString(struct.name);
          oprot.writeFieldEnd();
        }
      }
      if (struct.status != null) {
        if (struct.isSetStatus()) {
          oprot.writeFieldBegin(STATUS_FIELD_DESC);
          oprot.writeI32(struct.status.getValue());
          oprot.writeFieldEnd();
        }
      }
      if (struct.isSetQueryParallelism()) {
        oprot.writeFieldBegin(QUERY_PARALLELISM_FIELD_DESC);
        oprot.writeI32(struct.queryParallelism);
        oprot.writeFieldEnd();
      }
      if (struct.isSetIsSetQueryParallelism()) {
        oprot.writeFieldBegin(IS_SET_QUERY_PARALLELISM_FIELD_DESC);
        oprot.writeBool(struct.isSetQueryParallelism);
        oprot.writeFieldEnd();
      }
      if (struct.defaultPoolPath != null) {
        if (struct.isSetDefaultPoolPath()) {
          oprot.writeFieldBegin(DEFAULT_POOL_PATH_FIELD_DESC);
          oprot.writeString(struct.defaultPoolPath);
          oprot.writeFieldEnd();
        }
      }
      if (struct.isSetIsSetDefaultPoolPath()) {
        oprot.writeFieldBegin(IS_SET_DEFAULT_POOL_PATH_FIELD_DESC);
        oprot.writeBool(struct.isSetDefaultPoolPath);
        oprot.writeFieldEnd();
      }
      if (struct.ns != null) {
        if (struct.isSetNs()) {
          oprot.writeFieldBegin(NS_FIELD_DESC);
          oprot.writeString(struct.ns);
          oprot.writeFieldEnd();
        }
      }
      oprot.writeFieldStop();
      oprot.writeStructEnd();
    }

  }

  private static class WMNullableResourcePlanTupleSchemeFactory implements org.apache.thrift.scheme.SchemeFactory {
    public WMNullableResourcePlanTupleScheme getScheme() {
      return new WMNullableResourcePlanTupleScheme();
    }
  }

  private static class WMNullableResourcePlanTupleScheme extends org.apache.thrift.scheme.TupleScheme<WMNullableResourcePlan> {

    @Override
    public void write(org.apache.thrift.protocol.TProtocol prot, WMNullableResourcePlan struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TTupleProtocol oprot = (org.apache.thrift.protocol.TTupleProtocol) prot;
      java.util.BitSet optionals = new java.util.BitSet();
      if (struct.isSetName()) {
        optionals.set(0);
      }
      if (struct.isSetStatus()) {
        optionals.set(1);
      }
      if (struct.isSetQueryParallelism()) {
        optionals.set(2);
      }
      if (struct.isSetIsSetQueryParallelism()) {
        optionals.set(3);
      }
      if (struct.isSetDefaultPoolPath()) {
        optionals.set(4);
      }
      if (struct.isSetIsSetDefaultPoolPath()) {
        optionals.set(5);
      }
      if (struct.isSetNs()) {
        optionals.set(6);
      }
      oprot.writeBitSet(optionals, 7);
      if (struct.isSetName()) {
        oprot.writeString(struct.name);
      }
      if (struct.isSetStatus()) {
        oprot.writeI32(struct.status.getValue());
      }
      if (struct.isSetQueryParallelism()) {
        oprot.writeI32(struct.queryParallelism);
      }
      if (struct.isSetIsSetQueryParallelism()) {
        oprot.writeBool(struct.isSetQueryParallelism);
      }
      if (struct.isSetDefaultPoolPath()) {
        oprot.writeString(struct.defaultPoolPath);
      }
      if (struct.isSetIsSetDefaultPoolPath()) {
        oprot.writeBool(struct.isSetDefaultPoolPath);
      }
      if (struct.isSetNs()) {
        oprot.writeString(struct.ns);
      }
    }

    @Override
    public void read(org.apache.thrift.protocol.TProtocol prot, WMNullableResourcePlan struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TTupleProtocol iprot = (org.apache.thrift.protocol.TTupleProtocol) prot;
      java.util.BitSet incoming = iprot.readBitSet(7);
      if (incoming.get(0)) {
        struct.name = iprot.readString();
        struct.setNameIsSet(true);
      }
      if (incoming.get(1)) {
        struct.status = org.apache.hadoop.hive.metastore.api.WMResourcePlanStatus.findByValue(iprot.readI32());
        struct.setStatusIsSet(true);
      }
      if (incoming.get(2)) {
        struct.queryParallelism = iprot.readI32();
        struct.setQueryParallelismIsSet(true);
      }
      if (incoming.get(3)) {
        struct.isSetQueryParallelism = iprot.readBool();
        struct.setIsSetQueryParallelismIsSet(true);
      }
      if (incoming.get(4)) {
        struct.defaultPoolPath = iprot.readString();
        struct.setDefaultPoolPathIsSet(true);
      }
      if (incoming.get(5)) {
        struct.isSetDefaultPoolPath = iprot.readBool();
        struct.setIsSetDefaultPoolPathIsSet(true);
      }
      if (incoming.get(6)) {
        struct.ns = iprot.readString();
        struct.setNsIsSet(true);
      }
    }
  }

  private static <S extends org.apache.thrift.scheme.IScheme> S scheme(org.apache.thrift.protocol.TProtocol proto) {
    return (org.apache.thrift.scheme.StandardScheme.class.equals(proto.getScheme()) ? STANDARD_SCHEME_FACTORY : TUPLE_SCHEME_FACTORY).getScheme();
  }
}

