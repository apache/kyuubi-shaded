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

class FireEventResponse
{
    static public $isValidate = false;

    static public $_TSPEC = array(
        1 => array(
            'var' => 'eventIds',
            'isRequired' => false,
            'type' => TType::LST,
            'etype' => TType::I64,
            'elem' => array(
                'type' => TType::I64,
                ),
        ),
    );

    /**
     * @var int[]
     */
    public $eventIds = null;

    public function __construct($vals = null)
    {
        if (is_array($vals)) {
            if (isset($vals['eventIds'])) {
                $this->eventIds = $vals['eventIds'];
            }
        }
    }

    public function getName()
    {
        return 'FireEventResponse';
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
                        $this->eventIds = array();
                        $_size906 = 0;
                        $_etype909 = 0;
                        $xfer += $input->readListBegin($_etype909, $_size906);
                        for ($_i910 = 0; $_i910 < $_size906; ++$_i910) {
                            $elem911 = null;
                            $xfer += $input->readI64($elem911);
                            $this->eventIds []= $elem911;
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
        $xfer += $output->writeStructBegin('FireEventResponse');
        if ($this->eventIds !== null) {
            if (!is_array($this->eventIds)) {
                throw new TProtocolException('Bad type in structure.', TProtocolException::INVALID_DATA);
            }
            $xfer += $output->writeFieldBegin('eventIds', TType::LST, 1);
            $output->writeListBegin(TType::I64, count($this->eventIds));
            foreach ($this->eventIds as $iter912) {
                $xfer += $output->writeI64($iter912);
            }
            $output->writeListEnd();
            $xfer += $output->writeFieldEnd();
        }
        $xfer += $output->writeFieldStop();
        $xfer += $output->writeStructEnd();
        return $xfer;
    }
}
