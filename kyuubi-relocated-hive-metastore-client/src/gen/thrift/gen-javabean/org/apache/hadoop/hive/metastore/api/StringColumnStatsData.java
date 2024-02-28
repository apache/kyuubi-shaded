/**
 * Autogenerated by Thrift Compiler (0.16.0)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
package org.apache.hadoop.hive.metastore.api;

@SuppressWarnings({"cast", "rawtypes", "serial", "unchecked", "unused"})
@javax.annotation.Generated(value = "Autogenerated by Thrift Compiler (0.16.0)")
@org.apache.hadoop.classification.InterfaceAudience.Public @org.apache.hadoop.classification.InterfaceStability.Stable public class StringColumnStatsData implements org.apache.thrift.TBase<StringColumnStatsData, StringColumnStatsData._Fields>, java.io.Serializable, Cloneable, Comparable<StringColumnStatsData> {
  private static final org.apache.thrift.protocol.TStruct STRUCT_DESC = new org.apache.thrift.protocol.TStruct("StringColumnStatsData");

  private static final org.apache.thrift.protocol.TField MAX_COL_LEN_FIELD_DESC = new org.apache.thrift.protocol.TField("maxColLen", org.apache.thrift.protocol.TType.I64, (short)1);
  private static final org.apache.thrift.protocol.TField AVG_COL_LEN_FIELD_DESC = new org.apache.thrift.protocol.TField("avgColLen", org.apache.thrift.protocol.TType.DOUBLE, (short)2);
  private static final org.apache.thrift.protocol.TField NUM_NULLS_FIELD_DESC = new org.apache.thrift.protocol.TField("numNulls", org.apache.thrift.protocol.TType.I64, (short)3);
  private static final org.apache.thrift.protocol.TField NUM_DVS_FIELD_DESC = new org.apache.thrift.protocol.TField("numDVs", org.apache.thrift.protocol.TType.I64, (short)4);
  private static final org.apache.thrift.protocol.TField BIT_VECTORS_FIELD_DESC = new org.apache.thrift.protocol.TField("bitVectors", org.apache.thrift.protocol.TType.STRING, (short)5);

  private static final org.apache.thrift.scheme.SchemeFactory STANDARD_SCHEME_FACTORY = new StringColumnStatsDataStandardSchemeFactory();
  private static final org.apache.thrift.scheme.SchemeFactory TUPLE_SCHEME_FACTORY = new StringColumnStatsDataTupleSchemeFactory();

  private long maxColLen; // required
  private double avgColLen; // required
  private long numNulls; // required
  private long numDVs; // required
  private @org.apache.thrift.annotation.Nullable java.nio.ByteBuffer bitVectors; // optional

  /** The set of fields this struct contains, along with convenience methods for finding and manipulating them. */
  public enum _Fields implements org.apache.thrift.TFieldIdEnum {
    MAX_COL_LEN((short)1, "maxColLen"),
    AVG_COL_LEN((short)2, "avgColLen"),
    NUM_NULLS((short)3, "numNulls"),
    NUM_DVS((short)4, "numDVs"),
    BIT_VECTORS((short)5, "bitVectors");

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
        case 1: // MAX_COL_LEN
          return MAX_COL_LEN;
        case 2: // AVG_COL_LEN
          return AVG_COL_LEN;
        case 3: // NUM_NULLS
          return NUM_NULLS;
        case 4: // NUM_DVS
          return NUM_DVS;
        case 5: // BIT_VECTORS
          return BIT_VECTORS;
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
  private static final int __MAXCOLLEN_ISSET_ID = 0;
  private static final int __AVGCOLLEN_ISSET_ID = 1;
  private static final int __NUMNULLS_ISSET_ID = 2;
  private static final int __NUMDVS_ISSET_ID = 3;
  private byte __isset_bitfield = 0;
  private static final _Fields optionals[] = {_Fields.BIT_VECTORS};
  public static final java.util.Map<_Fields, org.apache.thrift.meta_data.FieldMetaData> metaDataMap;
  static {
    java.util.Map<_Fields, org.apache.thrift.meta_data.FieldMetaData> tmpMap = new java.util.EnumMap<_Fields, org.apache.thrift.meta_data.FieldMetaData>(_Fields.class);
    tmpMap.put(_Fields.MAX_COL_LEN, new org.apache.thrift.meta_data.FieldMetaData("maxColLen", org.apache.thrift.TFieldRequirementType.REQUIRED, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.I64)));
    tmpMap.put(_Fields.AVG_COL_LEN, new org.apache.thrift.meta_data.FieldMetaData("avgColLen", org.apache.thrift.TFieldRequirementType.REQUIRED, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.DOUBLE)));
    tmpMap.put(_Fields.NUM_NULLS, new org.apache.thrift.meta_data.FieldMetaData("numNulls", org.apache.thrift.TFieldRequirementType.REQUIRED, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.I64)));
    tmpMap.put(_Fields.NUM_DVS, new org.apache.thrift.meta_data.FieldMetaData("numDVs", org.apache.thrift.TFieldRequirementType.REQUIRED, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.I64)));
    tmpMap.put(_Fields.BIT_VECTORS, new org.apache.thrift.meta_data.FieldMetaData("bitVectors", org.apache.thrift.TFieldRequirementType.OPTIONAL, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.STRING        , true)));
    metaDataMap = java.util.Collections.unmodifiableMap(tmpMap);
    org.apache.thrift.meta_data.FieldMetaData.addStructMetaDataMap(StringColumnStatsData.class, metaDataMap);
  }

  public StringColumnStatsData() {
  }

  public StringColumnStatsData(
    long maxColLen,
    double avgColLen,
    long numNulls,
    long numDVs)
  {
    this();
    this.maxColLen = maxColLen;
    setMaxColLenIsSet(true);
    this.avgColLen = avgColLen;
    setAvgColLenIsSet(true);
    this.numNulls = numNulls;
    setNumNullsIsSet(true);
    this.numDVs = numDVs;
    setNumDVsIsSet(true);
  }

  /**
   * Performs a deep copy on <i>other</i>.
   */
  public StringColumnStatsData(StringColumnStatsData other) {
    __isset_bitfield = other.__isset_bitfield;
    this.maxColLen = other.maxColLen;
    this.avgColLen = other.avgColLen;
    this.numNulls = other.numNulls;
    this.numDVs = other.numDVs;
    if (other.isSetBitVectors()) {
      this.bitVectors = org.apache.thrift.TBaseHelper.copyBinary(other.bitVectors);
    }
  }

  public StringColumnStatsData deepCopy() {
    return new StringColumnStatsData(this);
  }

  @Override
  public void clear() {
    setMaxColLenIsSet(false);
    this.maxColLen = 0;
    setAvgColLenIsSet(false);
    this.avgColLen = 0.0;
    setNumNullsIsSet(false);
    this.numNulls = 0;
    setNumDVsIsSet(false);
    this.numDVs = 0;
    this.bitVectors = null;
  }

  public long getMaxColLen() {
    return this.maxColLen;
  }

  public void setMaxColLen(long maxColLen) {
    this.maxColLen = maxColLen;
    setMaxColLenIsSet(true);
  }

  public void unsetMaxColLen() {
    __isset_bitfield = org.apache.thrift.EncodingUtils.clearBit(__isset_bitfield, __MAXCOLLEN_ISSET_ID);
  }

  /** Returns true if field maxColLen is set (has been assigned a value) and false otherwise */
  public boolean isSetMaxColLen() {
    return org.apache.thrift.EncodingUtils.testBit(__isset_bitfield, __MAXCOLLEN_ISSET_ID);
  }

  public void setMaxColLenIsSet(boolean value) {
    __isset_bitfield = org.apache.thrift.EncodingUtils.setBit(__isset_bitfield, __MAXCOLLEN_ISSET_ID, value);
  }

  public double getAvgColLen() {
    return this.avgColLen;
  }

  public void setAvgColLen(double avgColLen) {
    this.avgColLen = avgColLen;
    setAvgColLenIsSet(true);
  }

  public void unsetAvgColLen() {
    __isset_bitfield = org.apache.thrift.EncodingUtils.clearBit(__isset_bitfield, __AVGCOLLEN_ISSET_ID);
  }

  /** Returns true if field avgColLen is set (has been assigned a value) and false otherwise */
  public boolean isSetAvgColLen() {
    return org.apache.thrift.EncodingUtils.testBit(__isset_bitfield, __AVGCOLLEN_ISSET_ID);
  }

  public void setAvgColLenIsSet(boolean value) {
    __isset_bitfield = org.apache.thrift.EncodingUtils.setBit(__isset_bitfield, __AVGCOLLEN_ISSET_ID, value);
  }

  public long getNumNulls() {
    return this.numNulls;
  }

  public void setNumNulls(long numNulls) {
    this.numNulls = numNulls;
    setNumNullsIsSet(true);
  }

  public void unsetNumNulls() {
    __isset_bitfield = org.apache.thrift.EncodingUtils.clearBit(__isset_bitfield, __NUMNULLS_ISSET_ID);
  }

  /** Returns true if field numNulls is set (has been assigned a value) and false otherwise */
  public boolean isSetNumNulls() {
    return org.apache.thrift.EncodingUtils.testBit(__isset_bitfield, __NUMNULLS_ISSET_ID);
  }

  public void setNumNullsIsSet(boolean value) {
    __isset_bitfield = org.apache.thrift.EncodingUtils.setBit(__isset_bitfield, __NUMNULLS_ISSET_ID, value);
  }

  public long getNumDVs() {
    return this.numDVs;
  }

  public void setNumDVs(long numDVs) {
    this.numDVs = numDVs;
    setNumDVsIsSet(true);
  }

  public void unsetNumDVs() {
    __isset_bitfield = org.apache.thrift.EncodingUtils.clearBit(__isset_bitfield, __NUMDVS_ISSET_ID);
  }

  /** Returns true if field numDVs is set (has been assigned a value) and false otherwise */
  public boolean isSetNumDVs() {
    return org.apache.thrift.EncodingUtils.testBit(__isset_bitfield, __NUMDVS_ISSET_ID);
  }

  public void setNumDVsIsSet(boolean value) {
    __isset_bitfield = org.apache.thrift.EncodingUtils.setBit(__isset_bitfield, __NUMDVS_ISSET_ID, value);
  }

  public byte[] getBitVectors() {
    setBitVectors(org.apache.thrift.TBaseHelper.rightSize(bitVectors));
    return bitVectors == null ? null : bitVectors.array();
  }

  public java.nio.ByteBuffer bufferForBitVectors() {
    return org.apache.thrift.TBaseHelper.copyBinary(bitVectors);
  }

  public void setBitVectors(byte[] bitVectors) {
    this.bitVectors = bitVectors == null ? (java.nio.ByteBuffer)null   : java.nio.ByteBuffer.wrap(bitVectors.clone());
  }

  public void setBitVectors(@org.apache.thrift.annotation.Nullable java.nio.ByteBuffer bitVectors) {
    this.bitVectors = org.apache.thrift.TBaseHelper.copyBinary(bitVectors);
  }

  public void unsetBitVectors() {
    this.bitVectors = null;
  }

  /** Returns true if field bitVectors is set (has been assigned a value) and false otherwise */
  public boolean isSetBitVectors() {
    return this.bitVectors != null;
  }

  public void setBitVectorsIsSet(boolean value) {
    if (!value) {
      this.bitVectors = null;
    }
  }

  public void setFieldValue(_Fields field, @org.apache.thrift.annotation.Nullable java.lang.Object value) {
    switch (field) {
    case MAX_COL_LEN:
      if (value == null) {
        unsetMaxColLen();
      } else {
        setMaxColLen((java.lang.Long)value);
      }
      break;

    case AVG_COL_LEN:
      if (value == null) {
        unsetAvgColLen();
      } else {
        setAvgColLen((java.lang.Double)value);
      }
      break;

    case NUM_NULLS:
      if (value == null) {
        unsetNumNulls();
      } else {
        setNumNulls((java.lang.Long)value);
      }
      break;

    case NUM_DVS:
      if (value == null) {
        unsetNumDVs();
      } else {
        setNumDVs((java.lang.Long)value);
      }
      break;

    case BIT_VECTORS:
      if (value == null) {
        unsetBitVectors();
      } else {
        if (value instanceof byte[]) {
          setBitVectors((byte[])value);
        } else {
          setBitVectors((java.nio.ByteBuffer)value);
        }
      }
      break;

    }
  }

  @org.apache.thrift.annotation.Nullable
  public java.lang.Object getFieldValue(_Fields field) {
    switch (field) {
    case MAX_COL_LEN:
      return getMaxColLen();

    case AVG_COL_LEN:
      return getAvgColLen();

    case NUM_NULLS:
      return getNumNulls();

    case NUM_DVS:
      return getNumDVs();

    case BIT_VECTORS:
      return getBitVectors();

    }
    throw new java.lang.IllegalStateException();
  }

  /** Returns true if field corresponding to fieldID is set (has been assigned a value) and false otherwise */
  public boolean isSet(_Fields field) {
    if (field == null) {
      throw new java.lang.IllegalArgumentException();
    }

    switch (field) {
    case MAX_COL_LEN:
      return isSetMaxColLen();
    case AVG_COL_LEN:
      return isSetAvgColLen();
    case NUM_NULLS:
      return isSetNumNulls();
    case NUM_DVS:
      return isSetNumDVs();
    case BIT_VECTORS:
      return isSetBitVectors();
    }
    throw new java.lang.IllegalStateException();
  }

  @Override
  public boolean equals(java.lang.Object that) {
    if (that instanceof StringColumnStatsData)
      return this.equals((StringColumnStatsData)that);
    return false;
  }

  public boolean equals(StringColumnStatsData that) {
    if (that == null)
      return false;
    if (this == that)
      return true;

    boolean this_present_maxColLen = true;
    boolean that_present_maxColLen = true;
    if (this_present_maxColLen || that_present_maxColLen) {
      if (!(this_present_maxColLen && that_present_maxColLen))
        return false;
      if (this.maxColLen != that.maxColLen)
        return false;
    }

    boolean this_present_avgColLen = true;
    boolean that_present_avgColLen = true;
    if (this_present_avgColLen || that_present_avgColLen) {
      if (!(this_present_avgColLen && that_present_avgColLen))
        return false;
      if (this.avgColLen != that.avgColLen)
        return false;
    }

    boolean this_present_numNulls = true;
    boolean that_present_numNulls = true;
    if (this_present_numNulls || that_present_numNulls) {
      if (!(this_present_numNulls && that_present_numNulls))
        return false;
      if (this.numNulls != that.numNulls)
        return false;
    }

    boolean this_present_numDVs = true;
    boolean that_present_numDVs = true;
    if (this_present_numDVs || that_present_numDVs) {
      if (!(this_present_numDVs && that_present_numDVs))
        return false;
      if (this.numDVs != that.numDVs)
        return false;
    }

    boolean this_present_bitVectors = true && this.isSetBitVectors();
    boolean that_present_bitVectors = true && that.isSetBitVectors();
    if (this_present_bitVectors || that_present_bitVectors) {
      if (!(this_present_bitVectors && that_present_bitVectors))
        return false;
      if (!this.bitVectors.equals(that.bitVectors))
        return false;
    }

    return true;
  }

  @Override
  public int hashCode() {
    int hashCode = 1;

    hashCode = hashCode * 8191 + org.apache.thrift.TBaseHelper.hashCode(maxColLen);

    hashCode = hashCode * 8191 + org.apache.thrift.TBaseHelper.hashCode(avgColLen);

    hashCode = hashCode * 8191 + org.apache.thrift.TBaseHelper.hashCode(numNulls);

    hashCode = hashCode * 8191 + org.apache.thrift.TBaseHelper.hashCode(numDVs);

    hashCode = hashCode * 8191 + ((isSetBitVectors()) ? 131071 : 524287);
    if (isSetBitVectors())
      hashCode = hashCode * 8191 + bitVectors.hashCode();

    return hashCode;
  }

  @Override
  public int compareTo(StringColumnStatsData other) {
    if (!getClass().equals(other.getClass())) {
      return getClass().getName().compareTo(other.getClass().getName());
    }

    int lastComparison = 0;

    lastComparison = java.lang.Boolean.compare(isSetMaxColLen(), other.isSetMaxColLen());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetMaxColLen()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.maxColLen, other.maxColLen);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = java.lang.Boolean.compare(isSetAvgColLen(), other.isSetAvgColLen());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetAvgColLen()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.avgColLen, other.avgColLen);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = java.lang.Boolean.compare(isSetNumNulls(), other.isSetNumNulls());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetNumNulls()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.numNulls, other.numNulls);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = java.lang.Boolean.compare(isSetNumDVs(), other.isSetNumDVs());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetNumDVs()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.numDVs, other.numDVs);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = java.lang.Boolean.compare(isSetBitVectors(), other.isSetBitVectors());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetBitVectors()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.bitVectors, other.bitVectors);
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
    java.lang.StringBuilder sb = new java.lang.StringBuilder("StringColumnStatsData(");
    boolean first = true;

    sb.append("maxColLen:");
    sb.append(this.maxColLen);
    first = false;
    if (!first) sb.append(", ");
    sb.append("avgColLen:");
    sb.append(this.avgColLen);
    first = false;
    if (!first) sb.append(", ");
    sb.append("numNulls:");
    sb.append(this.numNulls);
    first = false;
    if (!first) sb.append(", ");
    sb.append("numDVs:");
    sb.append(this.numDVs);
    first = false;
    if (isSetBitVectors()) {
      if (!first) sb.append(", ");
      sb.append("bitVectors:");
      if (this.bitVectors == null) {
        sb.append("null");
      } else {
        org.apache.thrift.TBaseHelper.toString(this.bitVectors, sb);
      }
      first = false;
    }
    sb.append(")");
    return sb.toString();
  }

  public void validate() throws org.apache.thrift.TException {
    // check for required fields
    if (!isSetMaxColLen()) {
      throw new org.apache.thrift.protocol.TProtocolException("Required field 'maxColLen' is unset! Struct:" + toString());
    }

    if (!isSetAvgColLen()) {
      throw new org.apache.thrift.protocol.TProtocolException("Required field 'avgColLen' is unset! Struct:" + toString());
    }

    if (!isSetNumNulls()) {
      throw new org.apache.thrift.protocol.TProtocolException("Required field 'numNulls' is unset! Struct:" + toString());
    }

    if (!isSetNumDVs()) {
      throw new org.apache.thrift.protocol.TProtocolException("Required field 'numDVs' is unset! Struct:" + toString());
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
      // it doesn't seem like you should have to do this, but java serialization is wacky, and doesn't call the default constructor.
      __isset_bitfield = 0;
      read(new org.apache.thrift.protocol.TCompactProtocol(new org.apache.thrift.transport.TIOStreamTransport(in)));
    } catch (org.apache.thrift.TException te) {
      throw new java.io.IOException(te);
    }
  }

  private static class StringColumnStatsDataStandardSchemeFactory implements org.apache.thrift.scheme.SchemeFactory {
    public StringColumnStatsDataStandardScheme getScheme() {
      return new StringColumnStatsDataStandardScheme();
    }
  }

  private static class StringColumnStatsDataStandardScheme extends org.apache.thrift.scheme.StandardScheme<StringColumnStatsData> {

    public void read(org.apache.thrift.protocol.TProtocol iprot, StringColumnStatsData struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TField schemeField;
      iprot.readStructBegin();
      while (true)
      {
        schemeField = iprot.readFieldBegin();
        if (schemeField.type == org.apache.thrift.protocol.TType.STOP) { 
          break;
        }
        switch (schemeField.id) {
          case 1: // MAX_COL_LEN
            if (schemeField.type == org.apache.thrift.protocol.TType.I64) {
              struct.maxColLen = iprot.readI64();
              struct.setMaxColLenIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 2: // AVG_COL_LEN
            if (schemeField.type == org.apache.thrift.protocol.TType.DOUBLE) {
              struct.avgColLen = iprot.readDouble();
              struct.setAvgColLenIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 3: // NUM_NULLS
            if (schemeField.type == org.apache.thrift.protocol.TType.I64) {
              struct.numNulls = iprot.readI64();
              struct.setNumNullsIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 4: // NUM_DVS
            if (schemeField.type == org.apache.thrift.protocol.TType.I64) {
              struct.numDVs = iprot.readI64();
              struct.setNumDVsIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 5: // BIT_VECTORS
            if (schemeField.type == org.apache.thrift.protocol.TType.STRING) {
              struct.bitVectors = iprot.readBinary();
              struct.setBitVectorsIsSet(true);
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

    public void write(org.apache.thrift.protocol.TProtocol oprot, StringColumnStatsData struct) throws org.apache.thrift.TException {
      struct.validate();

      oprot.writeStructBegin(STRUCT_DESC);
      oprot.writeFieldBegin(MAX_COL_LEN_FIELD_DESC);
      oprot.writeI64(struct.maxColLen);
      oprot.writeFieldEnd();
      oprot.writeFieldBegin(AVG_COL_LEN_FIELD_DESC);
      oprot.writeDouble(struct.avgColLen);
      oprot.writeFieldEnd();
      oprot.writeFieldBegin(NUM_NULLS_FIELD_DESC);
      oprot.writeI64(struct.numNulls);
      oprot.writeFieldEnd();
      oprot.writeFieldBegin(NUM_DVS_FIELD_DESC);
      oprot.writeI64(struct.numDVs);
      oprot.writeFieldEnd();
      if (struct.bitVectors != null) {
        if (struct.isSetBitVectors()) {
          oprot.writeFieldBegin(BIT_VECTORS_FIELD_DESC);
          oprot.writeBinary(struct.bitVectors);
          oprot.writeFieldEnd();
        }
      }
      oprot.writeFieldStop();
      oprot.writeStructEnd();
    }

  }

  private static class StringColumnStatsDataTupleSchemeFactory implements org.apache.thrift.scheme.SchemeFactory {
    public StringColumnStatsDataTupleScheme getScheme() {
      return new StringColumnStatsDataTupleScheme();
    }
  }

  private static class StringColumnStatsDataTupleScheme extends org.apache.thrift.scheme.TupleScheme<StringColumnStatsData> {

    @Override
    public void write(org.apache.thrift.protocol.TProtocol prot, StringColumnStatsData struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TTupleProtocol oprot = (org.apache.thrift.protocol.TTupleProtocol) prot;
      oprot.writeI64(struct.maxColLen);
      oprot.writeDouble(struct.avgColLen);
      oprot.writeI64(struct.numNulls);
      oprot.writeI64(struct.numDVs);
      java.util.BitSet optionals = new java.util.BitSet();
      if (struct.isSetBitVectors()) {
        optionals.set(0);
      }
      oprot.writeBitSet(optionals, 1);
      if (struct.isSetBitVectors()) {
        oprot.writeBinary(struct.bitVectors);
      }
    }

    @Override
    public void read(org.apache.thrift.protocol.TProtocol prot, StringColumnStatsData struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TTupleProtocol iprot = (org.apache.thrift.protocol.TTupleProtocol) prot;
      struct.maxColLen = iprot.readI64();
      struct.setMaxColLenIsSet(true);
      struct.avgColLen = iprot.readDouble();
      struct.setAvgColLenIsSet(true);
      struct.numNulls = iprot.readI64();
      struct.setNumNullsIsSet(true);
      struct.numDVs = iprot.readI64();
      struct.setNumDVsIsSet(true);
      java.util.BitSet incoming = iprot.readBitSet(1);
      if (incoming.get(0)) {
        struct.bitVectors = iprot.readBinary();
        struct.setBitVectorsIsSet(true);
      }
    }
  }

  private static <S extends org.apache.thrift.scheme.IScheme> S scheme(org.apache.thrift.protocol.TProtocol proto) {
    return (org.apache.thrift.scheme.StandardScheme.class.equals(proto.getScheme()) ? STANDARD_SCHEME_FACTORY : TUPLE_SCHEME_FACTORY).getScheme();
  }
}

