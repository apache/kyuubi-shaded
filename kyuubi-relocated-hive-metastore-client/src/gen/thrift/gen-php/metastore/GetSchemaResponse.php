<?php
namespace metastore;

/**
 * Autogenerated by Thrift Compiler (0.16.0)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
use Thrift\Base\TBase;
use Thrift\Type\TType;
use Thrift\Type\TMessageType;
use Thrift\Exception\TException;
use Thrift\Exception\TProtocolException;
use Thrift\Protocol\TProtocol;
use Thrift\Protocol\TBinaryProtocolAccelerated;
use Thrift\Exception\TApplicationException;

class GetSchemaResponse
{
    static public $isValidate = false;

    static public $_TSPEC = array(
        1 => array(
            'var' => 'fields',
            'isRequired' => true,
            'type' => TType::LST,
            'etype' => TType::STRUCT,
            'elem' => array(
                'type' => TType::STRUCT,
                'class' => '\metastore\FieldSchema',
                ),
        ),
    );

    /**
     * @var \metastore\FieldSchema[]
     */
    public $fields = null;

    public function __construct($vals = null)
    {
        if (is_array($vals)) {
            if (isset($vals['fields'])) {
                $this->fields = $vals['fields'];
            }
        }
    }

    public function getName()
    {
        return 'GetSchemaResponse';
    }


    public function read($input)
    {
        $xfer = 0;
        $fname = null;
        $ftype = 0;
        $fid = 0;
        $xfer += $input->readStructBegin($fname);
        while (true) {
            $xfer += $input->readFieldBegin($fname, $ftype, $fid);
            if ($ftype == TType::STOP) {
                break;
            }
            switch ($fid) {
                case 1:
                    if ($ftype == TType::LST) {
                        $this->fields = array();
                        $_size1241 = 0;
                        $_etype1244 = 0;
                        $xfer += $input->readListBegin($_etype1244, $_size1241);
                        for ($_i1245 = 0; $_i1245 < $_size1241; ++$_i1245) {
                            $elem1246 = null;
                            $elem1246 = new \metastore\FieldSchema();
                            $xfer += $elem1246->read($input);
                            $this->fields []= $elem1246;
                        }
                        $xfer += $input->readListEnd();
                    } else {
                        $xfer += $input->skip($ftype);
                    }
                    break;
                default:
                    $xfer += $input->skip($ftype);
                    break;
            }
            $xfer += $input->readFieldEnd();
        }
        $xfer += $input->readStructEnd();
        return $xfer;
    }

    public function write($output)
    {
        $xfer = 0;
        $xfer += $output->writeStructBegin('GetSchemaResponse');
        if ($this->fields !== null) {
            if (!is_array($this->fields)) {
                throw new TProtocolException('Bad type in structure.', TProtocolException::INVALID_DATA);
            }
            $xfer += $output->writeFieldBegin('fields', TType::LST, 1);
            $output->writeListBegin(TType::STRUCT, count($this->fields));
            foreach ($this->fields as $iter1247) {
                $xfer += $iter1247->write($output);
            }
            $output->writeListEnd();
            $xfer += $output->writeFieldEnd();
        }
        $xfer += $output->writeFieldStop();
        $xfer += $output->writeStructEnd();
        return $xfer;
    }
}
