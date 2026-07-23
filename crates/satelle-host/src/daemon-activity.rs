use std::sync::{Arc, Mutex};

/// Process-local work that must keep an on-demand Host alive.
///
/// Durable records are intentionally outside this tracker. Only a live guard
/// contributes to the count, so retained Sessions and recovery records do not
/// turn persistence into process liveness.
#[derive(Debug, Default)]
pub(crate) struct DaemonActivity {
    state: Mutex<DaemonActivityState>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct DaemonActivityState {
    active: usize,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DaemonActivitySnapshot {
    active: usize,
    generation: u64,
}

impl DaemonActivitySnapshot {
    pub(crate) const fn is_idle(self) -> bool {
        self.active == 0
    }

    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }
}

impl DaemonActivity {
    pub(crate) fn begin(self: &Arc<Self>) -> DaemonActivityGuard {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.active += 1;
        state.generation = state.generation.wrapping_add(1);
        DaemonActivityGuard {
            activity: Arc::clone(self),
        }
    }

    pub(crate) fn snapshot(&self) -> DaemonActivitySnapshot {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        DaemonActivitySnapshot {
            active: state.active,
            generation: state.generation,
        }
    }
}

pub(crate) struct DaemonActivityGuard {
    activity: Arc<DaemonActivity>,
}

impl Drop for DaemonActivityGuard {
    fn drop(&mut self) {
        let mut state = self
            .activity
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.active -= 1;
        state.generation = state.generation.wrapping_add(1);
    }
}
