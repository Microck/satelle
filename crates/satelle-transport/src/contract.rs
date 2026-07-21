mod error;
mod events;
mod logs;
mod read;
mod session;
mod setup;

pub(crate) use error::ApiErrorCategory;
pub use error::{ApiError, ApiErrorCode};
pub(crate) use events::MAX_EVENT_SUBSCRIPTIONS;
pub use events::{
    EventSubscription, SubscribeRequest, SubscribeRequestError, SubscribedResponse, WsCloseReason,
    WsControlError, WsServerControl,
};
pub use logs::LogsPageResponse;
pub(crate) use read::effective_limits;
pub use read::{
    CapabilitiesResponse, EffectiveLimits, HostDesktopSessionsResponse, HostStatusResponse,
    LiveResponse,
};
pub(crate) use session::ApiRequestContract;
pub(crate) use session::TurnRequestParts;
pub use session::{
    AdmissionCancellationOutcome, AdmissionCancellationResponse, SessionResponse, StopRequest,
    StopResponse, TurnRequest,
};
pub use setup::{
    DURABLE_SETUP_PENDING_TTL, DurableTokenActivationResponse, DurableTokenConfirmationResponse,
    DurableTokenIssuanceResponse,
};

pub(crate) const PROTOCOL_VERSION_HEADER: &str = "satelle-protocol-version";
// Expected-Turn stop targeting is safety-critical. Bump the exact-match mutation protocol so
// older v3 daemons cannot silently ignore the header and stop a newer Turn.
pub(crate) const PROTOCOL_VERSION: &str = "4";

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use uuid::{Uuid, Variant, Version};

macro_rules! define_schema_token {
    ($name:ident, $token:literal) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        struct $name;

        impl $name {
            const TOKEN: &'static str = $token;
        }

        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(Self::TOKEN)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = <String as serde::Deserialize>::deserialize(deserializer)?;
                if value == Self::TOKEN {
                    Ok(Self)
                } else {
                    Err(serde::de::Error::custom(concat!(
                        "expected schema_version ",
                        $token
                    )))
                }
            }
        }
    };
}

pub(super) use define_schema_token;

pub(crate) trait AuthenticatedResponseContract {
    fn request_id(&self) -> &RequestId;
    fn host_identity(&self) -> &str;
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RequestId(String);

impl RequestId {
    pub fn new() -> Self {
        Self(Uuid::now_v7().hyphenated().to_string())
    }

    pub fn parse(value: &str) -> Result<Self, RequestIdError> {
        let uuid = Uuid::parse_str(value).map_err(|_| RequestIdError)?;
        if uuid.get_version() != Some(Version::SortRand)
            || uuid.get_variant() != Variant::RFC4122
            || value != uuid.hyphenated().to_string()
        {
            return Err(RequestIdError);
        }
        Ok(Self(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for RequestId {
    type Err = RequestIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for RequestId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RequestId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestIdError;

impl fmt::Display for RequestIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the request ID must be a canonical UUIDv7")
    }
}

impl std::error::Error for RequestIdError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_ids_accept_only_canonical_uuidv7() {
        let generated = RequestId::new();
        assert_eq!(RequestId::parse(generated.as_str()), Ok(generated));
        assert!(RequestId::parse("550e8400-e29b-41d4-a716-446655440000").is_err());
        assert!(RequestId::parse("not-a-request-id").is_err());
    }
}
