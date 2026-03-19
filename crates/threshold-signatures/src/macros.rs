/// Implements [`Debug`] for types containing secret cryptographic material,
/// ensuring secrets are never leaked through debug output.
///
/// # Fully redacted
/// When all fields are secret, outputs `TypeName(<redacted>)`:
/// ```ignore
/// impl_secret_debug!(ScalarWrapper);
/// ```
///
/// # Partially redacted
/// When some fields are public, shows public fields and redacts secret ones:
/// ```ignore
/// impl_secret_debug!(PresignOutput { show: [big_r], redact: [k, sigma] });
/// ```
///
/// # Generic types
/// Wrap bounds in braces to avoid macro ambiguity with `>`:
/// ```ignore
/// impl_secret_debug!({C: Ciphersuite} KeygenOutput<C> { show: [public_key], redact: [private_share] });
/// ```
///
/// # Custom format with metadata
/// When non-secret metadata should be included alongside the redaction:
/// ```ignore
/// impl_secret_debug!(BitMatrix, |self| "BitMatrix(<redacted>, height={})", self.0.len());
/// ```
macro_rules! impl_secret_debug {
    ($name:ident) => {
        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(f, concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
    ($name:ident { show: [$($show:ident),* $(,)?], redact: [$($redact:ident),* $(,)?] }) => {
        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_struct(stringify!($name))
                    $(.field(stringify!($show), &self.$show))*
                    $(.field(stringify!($redact), &"<redacted>"))*
                    .finish()
            }
        }
    };
    ({ $($impl_generics:tt)* } $name:ident < $($type_param:ident),+ > { show: [$($show:ident),* $(,)?], redact: [$($redact:ident),* $(,)?] }) => {
        impl< $($impl_generics)* > ::core::fmt::Debug for $name< $($type_param),+ > {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_struct(stringify!($name))
                    $(.field(stringify!($show), &self.$show))*
                    $(.field(stringify!($redact), &"<redacted>"))*
                    .finish()
            }
        }
    };
    ($name:ident, |$self:ident| $fmt:literal $(, $arg:expr)*) => {
        impl ::core::fmt::Debug for $name {
            fn fmt(&$self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(f, $fmt $(, $arg)*)
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    // Arm 1: fully redacted
    struct FullyRedacted {
        _secret: u64,
    }
    impl_secret_debug!(FullyRedacted);

    #[test]
    fn fully_redacted_hides_all_fields() {
        let val = FullyRedacted { _secret: 42 };
        let debug = format!("{:?}", val);
        assert_eq!(debug, "FullyRedacted(<redacted>)");
        assert!(!debug.contains("42"));
    }

    // Arm 2: show/redact fields
    struct PartiallyRedacted {
        public_id: u32,
        secret_key: &'static str,
    }
    impl_secret_debug!(PartiallyRedacted { show: [public_id], redact: [secret_key] });

    #[test]
    fn partially_redacted_shows_public_and_hides_secret() {
        let val = PartiallyRedacted {
            public_id: 7,
            secret_key: "super_secret_value",
        };
        let debug = format!("{:?}", val);
        assert!(debug.contains("public_id"));
        assert!(debug.contains("7"));
        assert!(debug.contains("secret_key"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("super_secret_value"));
    }

    // Arm 3: generic type with show/redact
    trait Dummy {}
    struct GenericRedacted<T: Dummy> {
        visible: u32,
        hidden: u64,
        _marker: PhantomData<T>,
    }
    impl_secret_debug!({T: Dummy} GenericRedacted<T> { show: [visible], redact: [hidden] });

    struct ConcreteDummy;
    impl Dummy for ConcreteDummy {}

    #[test]
    fn generic_type_shows_public_and_hides_secret() {
        let val = GenericRedacted::<ConcreteDummy> {
            visible: 1,
            hidden: 99,
            _marker: PhantomData,
        };
        let debug = format!("{:?}", val);
        assert!(debug.contains("visible"));
        assert!(debug.contains("1"));
        assert!(debug.contains("hidden"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("99"));
    }

    // Arm 4: custom format with metadata
    struct CustomFormat(Vec<u8>);
    impl_secret_debug!(CustomFormat, |self| "CustomFormat(<redacted>, len={})", self.0.len());

    #[test]
    fn custom_format_shows_metadata_but_not_contents() {
        let val = CustomFormat(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let debug = format!("{:?}", val);
        assert_eq!(debug, "CustomFormat(<redacted>, len=4)");
        assert!(!debug.contains("DE"));
    }
}
