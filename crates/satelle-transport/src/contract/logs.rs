use super::{AuthenticatedResponseContract, RequestId, define_schema_token};
use satelle_host::DaemonLogPage;
use serde::{Deserialize, Serialize};

define_schema_token!(LogsPageSchema, "satelle.logs.page.v1");

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogsPageResponse {
    schema_version: LogsPageSchema,
    request_id: RequestId,
    host_identity: String,
    #[serde(flatten)]
    page: DaemonLogPage,
}

impl LogsPageResponse {
    pub(crate) fn new(request_id: RequestId, host_identity: String, page: DaemonLogPage) -> Self {
        Self {
            schema_version: LogsPageSchema,
            request_id,
            host_identity,
            page,
        }
    }

    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn host_identity(&self) -> &str {
        &self.host_identity
    }

    pub const fn page(&self) -> &DaemonLogPage {
        &self.page
    }
}

impl AuthenticatedResponseContract for LogsPageResponse {
    fn request_id(&self) -> &RequestId {
        self.request_id()
    }

    fn host_identity(&self) -> &str {
        self.host_identity()
    }

    fn matches_host_identity(&self, expected_host_identity: &str) -> bool {
        // Entries are flattened under this authenticated envelope, so each
        // nested identity must remain bound to the Host that produced it.
        self.host_identity() == expected_host_identity
            && self
                .page()
                .entries()
                .iter()
                .all(|entry| entry.host_identity().as_str() == expected_host_identity)
    }
}
