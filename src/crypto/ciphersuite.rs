// Generic Ciphersuite Trait
use frost_core::Group;

pub enum BytesOrder {
    BigEndian,
    LittleEndian,
}

pub trait ScalarSerializationFormat {
    fn bytes_order() -> BytesOrder;
}
pub trait Ciphersuite: frost_core::Ciphersuite + ScalarSerializationFormat {}

pub type Element<C> = <<C as frost_core::Ciphersuite>::Group as Group>::Element;
