// Generic Ciphersuite Trait

pub enum BytesOrder {
    BigEndian,
    LittleEndian,
}

pub trait ScalarSerializationFormat {
    fn bytes_order() -> BytesOrder;
}
pub trait Ciphersuite: frost_core::Ciphersuite + ScalarSerializationFormat {}
