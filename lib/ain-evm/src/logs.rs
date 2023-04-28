use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use ethereum::Log;
use primitive_types::{H160, H256, U256};
use ethbloom::Bloom;
use crate::traits::{PersistentState, PersistentStateError};

pub struct LogsStruct {
    pub address: H160,
    pub block_hash: H256,
    pub logs: Vec<Log>
}

pub static LOGS_PATH: &str = "logs.bin";

type LogsBlockToLogs = HashMap<H256, Log>;
type AddressToLogsBlock = HashMap<H160, LogsBlockToLogs>;


pub struct LogsHandler {
    pub logs: Arc<RwLock<AddressToLogsBlock>>,
}

impl PersistentState for AddressToLogsBlock {}

impl Default for LogsHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl LogsHandler {
    pub fn new() -> Self {
        Self {
            logs: Arc::new(RwLock::new(
                AddressToLogsBlock::load_from_disk(LOGS_PATH).unwrap(),
            )),
        }
    }

    pub fn flush(&self) -> Result<(), PersistentStateError> {
        self.logs
            .write()
            .unwrap()
            .save_to_disk(LOGS_PATH)
    }

    pub fn generate_logs(&self, responses: Vec<LogsStruct>) -> Bloom {
        let log_writer = self.logs.write().unwrap();

        for response in responses {
            let mut logs = log_writer.get(&response.address).unwrap_or(&HashMap::new());

            for log in response.logs {
                logs.insert(response.block_hash, log);
            }
        }
        return Bloom::zero();
    }
}