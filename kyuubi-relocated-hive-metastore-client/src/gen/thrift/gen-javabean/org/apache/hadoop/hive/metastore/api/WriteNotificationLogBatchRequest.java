/**
 * Autogenerated by Thrift Compiler (0.16.0)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
package org.apache.hadoop.hive.metastore.api;

@SuppressWarnings({"cast", "rawtypes", "serial", "unchecked", "unused"})
@javax.annotation.Generated(value = "Autogenerated by Thrift Compiler (0.16.0)")
@org.apache.hadoop.classification.InterfaceAudience.Public @org.apache.hadoop.classification.InterfaceStability.Stable public class WriteNotificationLogBatchRequest implements org.apache.thrift.TBase<WriteNotificationLogBatchRequest, WriteNotificationLogBatchRequest._Fields>, java.io.Serializable, Cloneable, Comparable<WriteNotificationLogBatchRequest> {
  private static final org.apache.thrift.protocol.TStruct STRUCT_DESC = new org.apache.thrift.protocol.TStruct("WriteNotificationLogBatchRequest");

  private static final org.apache.thrift.protocol.TField CATALOG_FIELD_DESC = new org.apache.thrift.protocol.TField("catalog", org.apache.thrift.protocol.TType.STRING, (short)1);
  private static final org.apache.thrift.protocol.TField DB_FIELD_DESC = new org.apache.thrift.protocol.TField("db", org.apache.thrift.protocol.TType.STRING, (short)2);
  private static final org.apache.thrift.protocol.TField TABLE_FIELD_DESC = new org.apache.thrift.protocol.TField("table", org.apache.thrift.protocol.TType.STRING, (short)3);
  private static final org.apache.thrift.protocol.TField REQUEST_LIST_FIELD_DESC = new org.apache.thrift.protocol.TField("requestList", org.apache.thrift.protocol.TType.LIST, (short)4);

  private static final org.apache.thrift.scheme.SchemeFactory STANDARD_SCHEME_FACTORY = new WriteNotificationLogBatchRequestStandardSchemeFactory();
  private static final org.apache.thrift.scheme.SchemeFactory TUPLE_SCHEME_FACTORY = new WriteNotificationLogBatchRequestTupleSchemeFactory();

  private @org.apache.thrift.annotation.Nullable java.lang.String catalog; // required
  private @org.apache.thrift.annotation.Nullable java.lang.String db; // required
  private @org.apache.thrift.annotation.Nullable java.lang.String table; // required
  private @org.apache.thrift.annotation.Nullable java.util.List<WriteNotificationLogRequest> requestList; // required

  /** The set of fields this struct contains, along with convenience methods for finding and manipulating them. */
  public enum _Fields implements org.apache.thrift.TFieldIdEnum {
    CATALOG((short)1, "catalog"),
    DB((short)2, "db"),
    TABLE((short)3, "table"),
    REQUEST_LIST((short)4, "requestList");

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
        case 1: // CATALOG
          return CATALOG;
        case 2: // DB
          return DB;
        case 3: // TABLE
          return TABLE;
        case 4: // REQUEST_LIST
          return REQUEST_LIST;
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
  public static final java.util.Map<_Fields, org.apache.thrift.meta_data.FieldMetaData> metaDataMap;
  static {
    java.util.Map<_Fields, org.apache.thrift.meta_data.FieldMetaData> tmpMap = new java.util.EnumMap<_Fields, org.apache.thrift.meta_data.FieldMetaData>(_Fields.class);
    tmpMap.put(_Fields.CATALOG, new org.apache.thrift.meta_data.FieldMetaData("catalog", org.apache.thrift.TFieldRequirementType.REQUIRED, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.STRING)));
    tmpMap.put(_Fields.DB, new org.apache.thrift.meta_data.FieldMetaData("db", org.apache.thrift.TFieldRequirementType.REQUIRED, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.STRING)));
    tmpMap.put(_Fields.TABLE, new org.apache.thrift.meta_data.FieldMetaData("table", org.apache.thrift.TFieldRequirementType.REQUIRED, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.STRING)));
    tmpMap.put(_Fields.REQUEST_LIST, new org.apache.thrift.meta_data.FieldMetaData("requestList", org.apache.thrift.TFieldRequirementType.REQUIRED, 
        new org.apache.thrift.meta_data.ListMetaData(org.apache.thrift.protocol.TType.LIST, 
            new org.apache.thrift.meta_data.StructMetaData(org.apache.thrift.protocol.TType.STRUCT, WriteNotificationLogRequest.class))));
    metaDataMap = java.util.Collections.unmodifiableMap(tmpMap);
    org.apache.thrift.meta_data.FieldMetaData.addStructMetaDataMap(WriteNotificationLogBatchRequest.class, metaDataMap);
  }

  public WriteNotificationLogBatchRequest() {
  }

  public WriteNotificationLogBatchRequest(
    java.lang.String catalog,
    java.lang.String db,
    java.lang.String table,
    java.util.List<WriteNotificationLogRequest> requestList)
  {
    this();
    this.catalog = catalog;
    this.db = db;
    this.table = table;
    this.requestList = requestList;
  }

  /**
   * Performs a deep copy on <i>other</i>.
   */
  public WriteNotificationLogBatchRequest(WriteNotificationLogBatchRequest other) {
    if (other.isSetCatalog()) {
      this.catalog = other.catalog;
    }
    if (other.isSetDb()) {
      this.db = other.db;
    }
    if (other.isSetTable()) {
      this.table = other.table;
    }
    if (other.isSetRequestList()) {
      java.util.List<WriteNotificationLogRequest> __this__requestList = new java.util.ArrayList<WriteNotificationLogRequest>(other.requestList.size());
      for (WriteNotificationLogRequest other_element : other.requestList) {
        __this__requestList.add(new WriteNotificationLogRequest(other_element));
      }
      this.requestList = __this__requestList;
    }
  }

  public WriteNotificationLogBatchRequest deepCopy() {
    return new WriteNotificationLogBatchRequest(this);
  }

  @Override
  public void clear() {
    this.catalog = null;
    this.db = null;
    this.table = null;
    this.requestList = null;
  }

  @org.apache.thrift.annotation.Nullable
  public java.lang.String getCatalog() {
    return this.catalog;
  }

  public void setCatalog(@org.apache.thrift.annotation.Nullable java.lang.String catalog) {
    this.catalog = catalog;
  }

  public void unsetCatalog() {
    this.catalog = null;
  }

  /** Returns true if field catalog is set (has been assigned a value) and false otherwise */
  public boolean isSetCatalog() {
    return this.catalog != null;
  }

  public void setCatalogIsSet(boolean value) {
    if (!value) {
      this.catalog = null;
    }
  }

  @org.apache.thrift.annotation.Nullable
  public java.lang.String getDb() {
    return this.db;
  }

  public void setDb(@org.apache.thrift.annotation.Nullable java.lang.String db) {
    this.db = db;
  }

  public void unsetDb() {
    this.db = null;
  }

  /** Returns true if field db is set (has been assigned a value) and false otherwise */
  public boolean isSetDb() {
    return this.db != null;
  }

  public void setDbIsSet(boolean value) {
    if (!value) {
      this.db = null;
    }
  }

  @org.apache.thrift.annotation.Nullable
  public java.lang.String getTable() {
    return this.table;
  }

  public void setTable(@org.apache.thrift.annotation.Nullable java.lang.String table) {
    this.table = table;
  }

  public void unsetTable() {
    this.table = null;
  }

  /** Returns true if field table is set (has been assigned a value) and false otherwise */
  public boolean isSetTable() {
    return this.table != null;
  }

  public void setTableIsSet(boolean value) {
    if (!value) {
      this.table = null;
    }
  }

  public int getRequestListSize() {
    return (this.requestList == null) ? 0 : this.requestList.size();
  }

  @org.apache.thrift.annotation.Nullable
  public java.util.Iterator<WriteNotificationLogRequest> getRequestListIterator() {
    return (this.requestList == null) ? null : this.requestList.iterator();
  }

  public void addToRequestList(WriteNotificationLogRequest elem) {
    if (this.requestList == null) {
      this.requestList = new java.util.ArrayList<WriteNotificationLogRequest>();
    }
    this.requestList.add(elem);
  }

  @org.apache.thrift.annotation.Nullable
  public java.util.List<WriteNotificationLogRequest> getRequestList() {
    return this.requestList;
  }

  public void setRequestList(@org.apache.thrift.annotation.Nullable java.util.List<WriteNotificationLogRequest> requestList) {
    this.requestList = requestList;
  }

  public void unsetRequestList() {
    this.requestList = null;
  }

  /** Returns true if field requestList is set (has been assigned a value) and false otherwise */
  public boolean isSetRequestList() {
    return this.requestList != null;
  }

  public void setRequestListIsSet(boolean value) {
    if (!value) {
      this.requestList = null;
    }
  }

  public void setFieldValue(_Fields field, @org.apache.thrift.annotation.Nullable java.lang.Object value) {
    switch (field) {
    case CATALOG:
      if (value == null) {
        unsetCatalog();
      } else {
        setCatalog((java.lang.String)value);
      }
      break;

    case DB:
      if (value == null) {
        unsetDb();
      } else {
        setDb((java.lang.String)value);
      }
      break;

    case TABLE:
      if (value == null) {
        unsetTable();
      } else {
        setTable((java.lang.String)value);
      }
      break;

    case REQUEST_LIST:
      if (value == null) {
        unsetRequestList();
      } else {
        setRequestList((java.util.List<WriteNotificationLogRequest>)value);
      }
      break;

    }
  }

  @org.apache.thrift.annotation.Nullable
  public java.lang.Object getFieldValue(_Fields field) {
    switch (field) {
    case CATALOG:
      return getCatalog();

    case DB:
      return getDb();

    case TABLE:
      return getTable();

    case REQUEST_LIST:
      return getRequestList();

    }
    throw new java.lang.IllegalStateException();
  }

  /** Returns true if field corresponding to fieldID is set (has been assigned a value) and false otherwise */
  public boolean isSet(_Fields field) {
    if (field == null) {
      throw new java.lang.IllegalArgumentException();
    }

    switch (field) {
    case CATALOG:
      return isSetCatalog();
    case DB:
      return isSetDb();
    case TABLE:
      return isSetTable();
    case REQUEST_LIST:
      return isSetRequestList();
    }
    throw new java.lang.IllegalStateException();
  }

  @Override
  public boolean equals(java.lang.Object that) {
    if (that instanceof WriteNotificationLogBatchRequest)
      return this.equals((WriteNotificationLogBatchRequest)that);
    return false;
  }

  public boolean equals(WriteNotificationLogBatchRequest that) {
    if (that == null)
      return false;
    if (this == that)
      return true;

    boolean this_present_catalog = true && this.isSetCatalog();
    boolean that_present_catalog = true && that.isSetCatalog();
    if (this_present_catalog || that_present_catalog) {
      if (!(this_present_catalog && that_present_catalog))
        return false;
      if (!this.catalog.equals(that.catalog))
        return false;
    }

    boolean this_present_db = true && this.isSetDb();
    boolean that_present_db = true && that.isSetDb();
    if (this_present_db || that_present_db) {
      if (!(this_present_db && that_present_db))
        return false;
      if (!this.db.equals(that.db))
        return false;
    }

    boolean this_present_table = true && this.isSetTable();
    boolean that_present_table = true && that.isSetTable();
    if (this_present_table || that_present_table) {
      if (!(this_present_table && that_present_table))
        return false;
      if (!this.table.equals(that.table))
        return false;
    }

    boolean this_present_requestList = true && this.isSetRequestList();
    boolean that_present_requestList = true && that.isSetRequestList();
    if (this_present_requestList || that_present_requestList) {
      if (!(this_present_requestList && that_present_requestList))
        return false;
      if (!this.requestList.equals(that.requestList))
        return false;
    }

    return true;
  }

  @Override
  public int hashCode() {
    int hashCode = 1;

    hashCode = hashCode * 8191 + ((isSetCatalog()) ? 131071 : 524287);
    if (isSetCatalog())
      hashCode = hashCode * 8191 + catalog.hashCode();

    hashCode = hashCode * 8191 + ((isSetDb()) ? 131071 : 524287);
    if (isSetDb())
      hashCode = hashCode * 8191 + db.hashCode();

    hashCode = hashCode * 8191 + ((isSetTable()) ? 131071 : 524287);
    if (isSetTable())
      hashCode = hashCode * 8191 + table.hashCode();

    hashCode = hashCode * 8191 + ((isSetRequestList()) ? 131071 : 524287);
    if (isSetRequestList())
      hashCode = hashCode * 8191 + requestList.hashCode();

    return hashCode;
  }

  @Override
  public int compareTo(WriteNotificationLogBatchRequest other) {
    if (!getClass().equals(other.getClass())) {
      return getClass().getName().compareTo(other.getClass().getName());
    }

    int lastComparison = 0;

    lastComparison = java.lang.Boolean.compare(isSetCatalog(), other.isSetCatalog());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetCatalog()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.catalog, other.catalog);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = java.lang.Boolean.compare(isSetDb(), other.isSetDb());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetDb()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.db, other.db);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = java.lang.Boolean.compare(isSetTable(), other.isSetTable());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetTable()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.table, other.table);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = java.lang.Boolean.compare(isSetRequestList(), other.isSetRequestList());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetRequestList()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.requestList, other.requestList);
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
    java.lang.StringBuilder sb = new java.lang.StringBuilder("WriteNotificationLogBatchRequest(");
    boolean first = true;

    sb.append("catalog:");
    if (this.catalog == null) {
      sb.append("null");
    } else {
      sb.append(this.catalog);
    }
    first = false;
    if (!first) sb.append(", ");
    sb.append("db:");
    if (this.db == null) {
      sb.append("null");
    } else {
      sb.append(this.db);
    }
    first = false;
    if (!first) sb.append(", ");
    sb.append("table:");
    if (this.table == null) {
      sb.append("null");
    } else {
      sb.append(this.table);
    }
    first = false;
    if (!first) sb.append(", ");
    sb.append("requestList:");
    if (this.requestList == null) {
      sb.append("null");
    } else {
      sb.append(this.requestList);
    }
    first = false;
    sb.append(")");
    return sb.toString();
  }

  public void validate() throws org.apache.thrift.TException {
    // check for required fields
    if (!isSetCatalog()) {
      throw new org.apache.thrift.protocol.TProtocolException("Required field 'catalog' is unset! Struct:" + toString());
    }

    if (!isSetDb()) {
      throw new org.apache.thrift.protocol.TProtocolException("Required field 'db' is unset! Struct:" + toString());
    }

    if (!isSetTable()) {
      throw new org.apache.thrift.protocol.TProtocolException("Required field 'table' is unset! Struct:" + toString());
    }

    if (!isSetRequestList()) {
      throw new org.apache.thrift.protocol.TProtocolException("Required field 'requestList' is unset! Struct:" + toString());
    }

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
      read(new org.apache.thrift.protocol.TCompactProtocol(new org.apache.thrift.transport.TIOStreamTransport(in)));
    } catch (org.apache.thrift.TException te) {
      throw new java.io.IOException(te);
    }
  }

  private static class WriteNotificationLogBatchRequestStandardSchemeFactory implements org.apache.thrift.scheme.SchemeFactory {
    public WriteNotificationLogBatchRequestStandardScheme getScheme() {
      return new WriteNotificationLogBatchRequestStandardScheme();
    }
  }

  private static class WriteNotificationLogBatchRequestStandardScheme extends org.apache.thrift.scheme.StandardScheme<WriteNotificationLogBatchRequest> {

    public void read(org.apache.thrift.protocol.TProtocol iprot, WriteNotificationLogBatchRequest struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TField schemeField;
      iprot.readStructBegin();
      while (true)
      {
        schemeField = iprot.readFieldBegin();
        if (schemeField.type == org.apache.thrift.protocol.TType.STOP) { 
          break;
        }
        switch (schemeField.id) {
          case 1: // CATALOG
            if (schemeField.type == org.apache.thrift.protocol.TType.STRING) {
              struct.catalog = iprot.readString();
              struct.setCatalogIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 2: // DB
            if (schemeField.type == org.apache.thrift.protocol.TType.STRING) {
              struct.db = iprot.readString();
              struct.setDbIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 3: // TABLE
            if (schemeField.type == org.apache.thrift.protocol.TType.STRING) {
              struct.table = iprot.readString();
              struct.setTableIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 4: // REQUEST_LIST
            if (schemeField.type == org.apache.thrift.protocol.TType.LIST) {
              {
                org.apache.thrift.protocol.TList _list1042 = iprot.readListBegin();
                struct.requestList = new java.util.ArrayList<WriteNotificationLogRequest>(_list1042.size);
                @org.apache.thrift.annotation.Nullable WriteNotificationLogRequest _elem1043;
                for (int _i1044 = 0; _i1044 < _list1042.size; ++_i1044)
                {
                  _elem1043 = new WriteNotificationLogRequest();
                  _elem1043.read(iprot);
                  struct.requestList.add(_elem1043);
                }
                iprot.readListEnd();
              }
              struct.setRequestListIsSet(true);
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

    public void write(org.apache.thrift.protocol.TProtocol oprot, WriteNotificationLogBatchRequest struct) throws org.apache.thrift.TException {
      struct.validate();

      oprot.writeStructBegin(STRUCT_DESC);
      if (struct.catalog != null) {
        oprot.writeFieldBegin(CATALOG_FIELD_DESC);
        oprot.writeString(struct.catalog);
        oprot.writeFieldEnd();
      }
      if (struct.db != null) {
        oprot.writeFieldBegin(DB_FIELD_DESC);
        oprot.writeString(struct.db);
        oprot.writeFieldEnd();
      }
      if (struct.table != null) {
        oprot.writeFieldBegin(TABLE_FIELD_DESC);
        oprot.writeString(struct.table);
        oprot.writeFieldEnd();
      }
      if (struct.requestList != null) {
        oprot.writeFieldBegin(REQUEST_LIST_FIELD_DESC);
        {
          oprot.writeListBegin(new org.apache.thrift.protocol.TList(org.apache.thrift.protocol.TType.STRUCT, struct.requestList.size()));
          for (WriteNotificationLogRequest _iter1045 : struct.requestList)
          {
            _iter1045.write(oprot);
          }
          oprot.writeListEnd();
        }
        oprot.writeFieldEnd();
      }
      oprot.writeFieldStop();
      oprot.writeStructEnd();
    }

  }

  private static class WriteNotificationLogBatchRequestTupleSchemeFactory implements org.apache.thrift.scheme.SchemeFactory {
    public WriteNotificationLogBatchRequestTupleScheme getScheme() {
      return new WriteNotificationLogBatchRequestTupleScheme();
    }
  }

  private static class WriteNotificationLogBatchRequestTupleScheme extends org.apache.thrift.scheme.TupleScheme<WriteNotificationLogBatchRequest> {

    @Override
    public void write(org.apache.thrift.protocol.TProtocol prot, WriteNotificationLogBatchRequest struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TTupleProtocol oprot = (org.apache.thrift.protocol.TTupleProtocol) prot;
      oprot.writeString(struct.catalog);
      oprot.writeString(struct.db);
      oprot.writeString(struct.table);
      {
        oprot.writeI32(struct.requestList.size());
        for (WriteNotificationLogRequest _iter1046 : struct.requestList)
        {
          _iter1046.write(oprot);
        }
      }
    }

    @Override
    public void read(org.apache.thrift.protocol.TProtocol prot, WriteNotificationLogBatchRequest struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TTupleProtocol iprot = (org.apache.thrift.protocol.TTupleProtocol) prot;
      struct.catalog = iprot.readString();
      struct.setCatalogIsSet(true);
      struct.db = iprot.readString();
      struct.setDbIsSet(true);
      struct.table = iprot.readString();
      struct.setTableIsSet(true);
      {
        org.apache.thrift.protocol.TList _list1047 = iprot.readListBegin(org.apache.thrift.protocol.TType.STRUCT);
        struct.requestList = new java.util.ArrayList<WriteNotificationLogRequest>(_list1047.size);
        @org.apache.thrift.annotation.Nullable WriteNotificationLogRequest _elem1048;
        for (int _i1049 = 0; _i1049 < _list1047.size; ++_i1049)
        {
          _elem1048 = new WriteNotificationLogRequest();
          _elem1048.read(iprot);
          struct.requestList.add(_elem1048);
        }
      }
      struct.setRequestListIsSet(true);
    }
  }

  private static <S extends org.apache.thrift.scheme.IScheme> S scheme(org.apache.thrift.protocol.TProtocol proto) {
    return (org.apache.thrift.scheme.StandardScheme.class.equals(proto.getScheme()) ? STANDARD_SCHEME_FACTORY : TUPLE_SCHEME_FACTORY).getScheme();
  }
}

