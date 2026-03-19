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
