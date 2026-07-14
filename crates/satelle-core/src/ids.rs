use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::error::Error;
use std::fmt;
use std::str::FromStr;
use uuid::{Uuid, Variant, Version};

const SESSION_ID_PREFIX: &str = "rs_";
const TURN_ID_PREFIX: &str = "rt_";

/// JSON Schema pattern for the canonical public Session identifier format.
pub const SESSION_ID_PATTERN: &str =
    "^rs_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$";

/// Explains why a public Satelle identifier could not be parsed.
///
/// The error deliberately does not retain the rejected input. Identifiers can
/// appear beside sensitive session metadata, so callers should be able to log
/// this error without also logging the original value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdParseError {
    Empty,
    InvalidPrefix { expected: &'static str },
    MalformedUuid,
    NonV7Uuid,
    InvalidUuidVariant,
    NonCanonicalUuid,
}

impl fmt::Display for IdParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("the identifier is empty"),
            Self::InvalidPrefix { expected } => {
                write!(formatter, "the identifier must start with {expected}")
            }
            Self::MalformedUuid => formatter.write_str("the identifier contains a malformed UUID"),
            Self::NonV7Uuid => formatter.write_str("the identifier UUID must be version 7"),
            Self::InvalidUuidVariant => {
                formatter.write_str("the identifier UUID must use the RFC 9562 variant")
            }
            Self::NonCanonicalUuid => formatter
                .write_str("the identifier UUID must use canonical lowercase hyphenated form"),
        }
    }
}

impl Error for IdParseError {}

fn generate_id(prefix: &'static str) -> String {
    // uuid's process-wide v7 context guarantees that values returned by
    // `now_v7` remain ordered even when several are generated in one
    // millisecond or the system clock moves backwards.
    format!("{prefix}{}", Uuid::now_v7().hyphenated())
}

fn parse_id(value: &str, prefix: &'static str) -> Result<String, IdParseError> {
    if value.is_empty() {
        return Err(IdParseError::Empty);
    }

    let uuid_text = value
        .strip_prefix(prefix)
        .ok_or(IdParseError::InvalidPrefix { expected: prefix })?;
    let uuid = Uuid::parse_str(uuid_text).map_err(|_| IdParseError::MalformedUuid)?;

    if uuid.get_version() != Some(Version::SortRand) {
        return Err(IdParseError::NonV7Uuid);
    }
    if uuid.get_variant() != Variant::RFC4122 {
        return Err(IdParseError::InvalidUuidVariant);
    }

    // Uuid::parse_str intentionally accepts several representations. Public
    // IDs accept only the one representation promised by Satelle's contract.
    if uuid_text != uuid.hyphenated().to_string() {
        return Err(IdParseError::NonCanonicalUuid);
    }

    Ok(value.to_owned())
}

macro_rules! define_public_id {
    ($name:ident, $prefix:expr, $expecting:literal) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Generates a new Satelle-owned, time-ordered UUIDv7 identifier.
            pub fn new() -> Self {
                Self(generate_id($prefix))
            }

            /// Parses the strict public representation of this identifier.
            pub fn parse(value: &str) -> Result<Self, IdParseError> {
                value.parse()
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = IdParseError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                parse_id(value, $prefix).map(Self)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct IdVisitor;

                impl Visitor<'_> for IdVisitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str($expecting)
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        value.parse().map_err(E::custom)
                    }
                }

                deserializer.deserialize_str(IdVisitor)
            }
        }
    };
}

define_public_id!(
    SessionId,
    SESSION_ID_PREFIX,
    "a Satelle Session identifier in rs_<canonical lowercase UUIDv7> form"
);
define_public_id!(
    TurnId,
    TURN_ID_PREFIX,
    "a Satelle Turn identifier in rt_<canonical lowercase UUIDv7> form"
);

#[cfg(test)]
mod tests {
    use super::*;

    const UUID_V7: &str = "01890a5d-ac96-7b7c-9f89-37c3d0a66e11";
    const UUID_V4: &str = "550e8400-e29b-41d4-a716-446655440000";

    #[test]
    fn session_ids_accept_only_the_session_prefix() {
        let id = SessionId::parse(&format!("rs_{UUID_V7}")).expect("valid session ID");

        assert_eq!(format!("rs_{UUID_V7}"), id.as_str());
        assert_eq!(format!("rs_{UUID_V7}"), id.to_string());
        assert_eq!(
            Err(IdParseError::InvalidPrefix { expected: "rs_" }),
            SessionId::parse(&format!("rt_{UUID_V7}"))
        );
    }

    #[test]
    fn turn_ids_accept_only_the_turn_prefix() {
        let id: TurnId = format!("rt_{UUID_V7}").parse().expect("valid turn ID");

        assert_eq!(format!("rt_{UUID_V7}"), id.as_str());
        assert_eq!(format!("rt_{UUID_V7}"), id.to_string());
        assert_eq!(
            Err(IdParseError::InvalidPrefix { expected: "rt_" }),
            TurnId::parse(&format!("rs_{UUID_V7}"))
        );
    }

    #[test]
    fn identifiers_reject_empty_and_malformed_values() {
        for value in ["", "rs_", "rs_not-a-uuid", "rs_01890a5d-ac96"] {
            let error = SessionId::parse(value).expect_err("invalid ID must be rejected");

            assert!(matches!(
                error,
                IdParseError::Empty | IdParseError::MalformedUuid
            ));
        }
    }

    #[test]
    fn identifiers_reject_non_v7_uuids() {
        assert_eq!(
            Err(IdParseError::NonV7Uuid),
            SessionId::parse(&format!("rs_{UUID_V4}"))
        );
        assert_eq!(
            Err(IdParseError::NonV7Uuid),
            TurnId::parse(&format!("rt_{UUID_V4}"))
        );
    }

    #[test]
    fn identifiers_reject_noncanonical_uuid_representations() {
        let uppercase = UUID_V7.to_ascii_uppercase();
        let simple = UUID_V7.replace('-', "");

        for value in [format!("rs_{uppercase}"), format!("rs_{simple}")] {
            assert_eq!(
                Err(IdParseError::NonCanonicalUuid),
                SessionId::parse(&value)
            );
        }
    }

    #[test]
    fn identifiers_reject_non_rfc_uuid_variants() {
        // The version nibble is 7, but the variant nibble (`0`) is not the
        // RFC 9562 variant used by UUIDv7.
        let wrong_variant = "01890a5d-ac96-7b7c-0f89-37c3d0a66e11";

        assert_eq!(
            Err(IdParseError::InvalidUuidVariant),
            SessionId::parse(&format!("rs_{wrong_variant}"))
        );
    }

    #[test]
    fn generated_identifiers_are_canonical_uuidv7_values() {
        let session_id = SessionId::new();
        let turn_id = TurnId::new();

        assert_generated_id(session_id.as_str(), "rs_");
        assert_generated_id(turn_id.as_str(), "rt_");
    }

    #[test]
    fn generated_identifiers_preserve_creation_order() {
        let session_ids: Vec<_> = (0..128).map(|_| SessionId::new()).collect();
        let turn_ids: Vec<_> = (0..128).map(|_| TurnId::new()).collect();

        assert!(session_ids.windows(2).all(|ids| ids[0] < ids[1]));
        assert!(turn_ids.windows(2).all(|ids| ids[0] < ids[1]));
    }

    #[test]
    fn serde_uses_the_strict_string_contract() {
        let session_text = format!("rs_{UUID_V7}");
        let session_id = SessionId::parse(&session_text).expect("valid session ID");

        let json = serde_json::to_string(&session_id).expect("serialize session ID");
        assert_eq!(format!("\"{session_text}\""), json);
        assert_eq!(
            session_id,
            serde_json::from_str::<SessionId>(&json).expect("deserialize session ID")
        );

        let uppercase_json = format!("\"rs_{}\"", UUID_V7.to_ascii_uppercase());
        assert!(serde_json::from_str::<SessionId>(&uppercase_json).is_err());
        assert!(serde_json::from_str::<SessionId>("42").is_err());
    }

    fn assert_generated_id(value: &str, prefix: &str) {
        let uuid_text = value
            .strip_prefix(prefix)
            .expect("generated ID uses its public prefix");
        let uuid = Uuid::parse_str(uuid_text).expect("generated ID contains a UUID");

        assert_eq!(Some(Version::SortRand), uuid.get_version());
        assert_eq!(Variant::RFC4122, uuid.get_variant());
        assert_eq!(uuid.hyphenated().to_string(), uuid_text);
    }
}
