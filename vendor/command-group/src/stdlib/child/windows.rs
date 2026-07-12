use std::{
    io::{Read, Result},
    mem,
    process::{Child, ChildStderr, ChildStdin, ChildStdout, ExitStatus},
    ptr,
};
use winapi::{
    shared::{
        basetsd::ULONG_PTR,
        minwindef::{DWORD, FALSE},
    },
    um::{
        handleapi::CloseHandle,
        ioapiset::GetQueuedCompletionStatus,
        jobapi2::TerminateJobObject,
        minwinbase::OVERLAPPED,
        winbase::INFINITE,
        winnt::{HANDLE, JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO},
    },
};

use crate::winres::*;

pub(super) struct ChildImp {
    inner: Child,
    handles: JobPort,
}

impl ChildImp {
    pub fn new(inner: Child, job: HANDLE, completion_port: HANDLE) -> Self {
        Self {
            inner,
            handles: JobPort::new(job, completion_port),
        }
    }

    pub(super) fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.inner.stdin.take()
    }

    pub(super) fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.inner.stdout.take()
    }

    pub(super) fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.inner.stderr.take()
    }

    pub fn inner(&mut self) -> &mut Child {
        &mut self.inner
    }

    pub fn into_inner(self) -> Child {
        // manually drop the completion port
        let its = mem::ManuallyDrop::new(self.handles);
        unsafe { CloseHandle(its.completion_port) };
        // we leave the job handle unclosed, otherwise the Child is useless
        // (as closing it will terminate the job)

        // extract the Child
        self.inner
    }

    pub fn kill(&mut self) -> Result<()> {
        res_bool(unsafe { TerminateJobObject(self.handles.job, 1) })
    }

    pub fn id(&self) -> u32 {
        self.inner.id()
    }

    fn wait_imp(&self, timeout: DWORD) -> Result<bool> {
        loop {
            let mut code: DWORD = 0;
            let mut key: ULONG_PTR = 0;
            let mut overlapped: *mut OVERLAPPED = ptr::null_mut();
            let result = unsafe {
                GetQueuedCompletionStatus(
                    self.handles.completion_port,
                    &mut code,
                    &mut key,
                    &mut overlapped,
                    timeout,
                )
            };

            // A zero-timeout poll with no queued packet means the job is
            // still active. Every other failure remains an I/O error.
            if timeout != INFINITE && result == FALSE && overlapped.is_null() {
                return Ok(false);
            }
            res_bool(result)?;

            // Job ports emit several lifecycle packets. Only this terminal
            // packet proves that every process in the job has exited.
            if code == JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO {
                return Ok(true);
            }
        }
    }

    pub fn wait(&mut self) -> Result<ExitStatus> {
        let _ = self.wait_imp(INFINITE)?;
        self.inner.wait()
    }

    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        if self.wait_imp(0)? {
            self.inner.try_wait()
        } else {
            Ok(None)
        }
    }

    pub(super) fn read_both(
        mut out_r: ChildStdout,
        out_v: &mut Vec<u8>,
        mut err_r: ChildStderr,
        err_v: &mut Vec<u8>,
    ) -> Result<()> {
        out_r.read_to_end(out_v)?;
        err_r.read_to_end(err_v)?;
        Ok(())
    }
}
