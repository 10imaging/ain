#[macro_use]
extern crate serde;
extern crate serde_json;

mod codegen;
pub mod rpc;

use env_logger::{Builder as LogBuilder, Env};
use jsonrpsee_core::server::rpc_module::Methods;
use jsonrpsee_core::server::rpc_module::RpcModule;
use jsonrpsee_http_server::HttpServerBuilder;
use log::Level;
use tonic::transport::Server;
use serde_json::json;

use crate::codegen::rpc::{BlockchainService, Client, EthService};

use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use ain_evm_runtime::{Runtime, RUNTIME};

#[cfg(test)]
mod tests;

lazy_static::lazy_static! {
    // RPC clients cached globally based on address so that clients can be instantiated at will
    static ref CLIENTS: RwLock<HashMap<String, Client>> = RwLock::new(HashMap::new());
}

#[derive(Serialize, Deserialize, Clone)]
struct Block {
    difficulty: String,
    extraData: String,
    gasLimit: String,
    gasUsed: String,
    hash: String,
    logsBloom: String,
    miner: String,
    mixHash: String,
    nonce: String,
    number: String,
    parentHash: String,
    receiptsRoot: String,
    sha3Uncles: String,
    size: String,
    stateRoot: String,
    timestamp: String,
    totalDifficulty: String,
    transactions: Vec<String>,
    transactionsRoot: String,
    uncles: Vec<String>,
}

pub fn add_json_rpc_server(runtime: &Runtime, addr: &str) -> Result<(), Box<dyn Error>> {
    log::info!("Starting JSON RPC server at {}", addr);
    let addr = addr.parse::<SocketAddr>()?;
    let handle = runtime.rt_handle.clone();
    let server = runtime.rt_handle.block_on(
        HttpServerBuilder::default()
            .custom_tokio_runtime(handle)
            .build(addr),
    )?;
    let mut methods: Methods = Methods::new();
    methods.merge(BlockchainService::new(Arc::clone(&runtime.handlers)).module()?)?;
    methods.merge(EthService::new(Arc::clone(&runtime.handlers)).module()?)?;

    let mut blockno: i32 = 1;

    let mut module = RpcModule::new(());
    module.register_method("eth_chainId", |_, _| Ok(format!("0x{:x}", 1132))).unwrap();
    module.register_method("net_version", |_, _| Ok(format!("{}", 1132))).unwrap();
    module.register_method("eth_blockNumber", |_, _| Ok(4)).unwrap();
    module.register_method("eth_getBalance", |_, _| Ok(format!("0x{:x}", 10i128 * i128::pow(10, 20)))).unwrap();

    let block: Block = serde_json::from_str(r#"{
        "difficulty": "0xbfabcdbd93dda",
        "extraData": "0x737061726b706f6f6c2d636e2d6e6f64652d3132",
        "gasLimit": "0x79f39e",
        "gasUsed": "0x79ccd3",
        "hash": "0xb3b10624f8f0f86eb50dd04688409e5cea4bd02d700bf6e79e9384d47d6a5a35",
        "logsBloom": "0x4848112002a2020aaa0812180045840210020005281600c80104264300080008000491220144461026015300100000128005018401002090a824a4150015410020140400d808440106689b29d0280b1005200007480ca950b15b010908814e01911000054202a020b05880b914642a0000300003010044044082075290283516be82504082003008c4d8d14462a8800c2990c88002a030140180036c220205201860402001014040180002006860810ec0a1100a14144148408118608200060461821802c081000042d0810104a8004510020211c088200420822a082040e10104c00d010064004c122692020c408a1aa2348020445403814002c800888208b1",
        "miner": "0x5a0b54d5dc17e0aadc383d2db43b0a0d3e029c4c",
        "mixHash": "0x3d1fdd16f15aeab72e7db1013b9f034ee33641d92f71c0736beab4e67d34c7a7",
        "nonce": "0x4ab7a1c01d8a8072",
        "number": "0x3",
        "parentHash": "0x61a8ad530a8a43e3583f8ec163f773ad370329b2375d66433eb82f005e1d6202",
        "receiptsRoot": "0x5eced534b3d84d3d732ddbc714f5fd51d98a941b28182b6efe6df3a0fe90004b",
        "sha3Uncles": "0x8a562e7634774d3e3a36698ac4915e37fc84a2cd0044cb84fa5d80263d2af4f6",
        "size": "0x41c7",
        "stateRoot": "0xf5208fffa2ba5a3f3a2f64ebd5ca3d098978bedd75f335f56b705d8715ee2305",
        "timestamp": "0x5b541449",
        "totalDifficulty": "0x12ac11391a2f3872fcd",
        "transactions": [
        "0xbb3a336e3f823ec18197f1e13ee875700f08f03e2cab75f0d0b118dabb44cba0",
        "0x25f65866dba34783200c25fb1c120b36326c9ad3a47e8bc34c3edbc9208f1378",
        "0x5336f5c4132ef00e8b469ecfd4ee0d6800f6bd60aefb1c62232cbce81c085ae2",
        "0xb87410cfe0a75c004f7637736b3de1e8f4e08e9e2b05ab963622a40a5505664d",
        "0x990857a27ec7cfd6dfd88015173adf81959b5abaff6eefbe8e9df6b0f40f2711",
        "0x3563ccb5734b7b5015122a20b558723afe992ff1109a04b57e02f26edd5a6a38",
        "0xd7885d9412cc494fbe680b016bf7402b633c34c66833b35cad59af2a4aff4f0b",
        "0x48e60927d6fb9ae76f69a6400490b5ffcb2f9da3105fad6c61f21256ef0c217c",
        "0x9e30af26ff3836c4b55af62ba134bc55db662cf1d396cca437d12a8195bfcbe4",
        "0x2476eeede4764c6871f50f3235ebeb9a56d33b41bc3bb1ce3c18c5d710a0609c",
        "0x1cd3520fbb1eb6f2f6f257ab7c3cba957806b0b87182baedb4f81c62868064c1",
        "0x78ae3aee0ff16d8ea4f394b7b80021804e1d9f35cdbb9c6189bb6cbf58bc52c4",
        "0xfcc75bad728b8d302ba0674ebe3122fc50e3b78fe4948ddfc0d37ee987e666ca",
        "0xd2175464d72bcc61b2e07aa3aac742b4184480d7a9f6ae5c2ba24d9c9bb9f304",
        "0x42b56b504e59e42a3dc94e740bb4231e6326daaac7a73ef93ee8db7b96ac5d71",
        "0xd42681091641cd2a71f18299e8e206d5659c3076b1c63adc26f5b7740e230d2b",
        "0x1202c354f0a00b31adf9e3d895e0c8f3896182bb3ab9fc69d6c21d31a1bf279c",
        "0xa5cea1f6957431caf589a8dbb58c102fb191b39967fbe8d26cecf6f28bb835da",
        "0x2045efeb2f5ea9176690ece680d3fd7ca9e945d0d572d17786810d323628f98c",
        "0xbf55d13976616a23114b724b14049eaaf91db3f1950320b5306006a6b648b24f",
        "0x9e5c5ea885eb1d6b1b3ffcf703e3381b7681f7420f35408d30ba93ec0cdf0792",
        "0x6f1a61dc4306ca5e976a1706afe1f32279548df98e0373c5fee0ea189ddb77a0",
        "0xc5c16b30c22ee4f90c3a2de70554f7975eb476592ff13c61986d760da6cf7f9d",
        "0xb09de28497227c0537df0a78797fa00407dcd04a4f90d9de602484b61f7bf169",
        "0x1bfea966fa7772a26b4b2c8add15ceedcb70a903618f5d4603d69f52b9954025",
        "0xe58be9c0e3cedd4444c76d1adc098ba40cbe21ef886b2bfc2edb6ed96ba8d966",
        "0x3a29096f712ccdafd56e9a3c635d4fe2e6224ac3666d466c21da66c8829bbfd6",
        "0x31feab77d7c1c87eb79af54193400c8edad16645e1ea5fcc10f2eaec51fe3992",
        "0x4e0278fce62dca8e23cfae6a020fcd3b2facc03244d54b964bbde424f902ffe1",
        "0x300239a64a50ad0e646c232f85cfa4f3d3ed30090cd574329c782d95c2b42532",
        "0x41755f354b06b4b8a452db1cc9b5c810c75b1bbe236603cbc0950c3c81b80c51",
        "0x1e3fbeffc326f1ffd8559c6024c12557e6014bc02c12d65dbc1baa4e1aed94b7",
        "0x4a459a32cf68e9b7697a3a656432b340d6d27c3d4a513e6cce770d63df99839a",
        "0x3ef484913d185de728c787a1053ec1444ec1c7a5827eecba521d3b406b088a89",
        "0x43afa584c21f27a2747a8397b00d3ec4b460d929b61b510d017f01037a3ded3f",
        "0x44e6a37a6c1d8696fa0537385b9d1bb535b2b3309b5482209e95b5b6c58fc8da",
        "0x2a8bca48147955efcfd697f1a97304ae4cc467a7778741c2c47e516610f0a876",
        "0x4c6bd64c8974f8b949cfe265da1c1bb997e3c886f024b38c99d170acc70b83df",
        "0x103f0cca1ae13600c5be5b217e92430a72b0471d05e283c105f5d0df36438b2a",
        "0x00a06bf6fbd07b3a89ef9031a2108c8fa31b467b33a6edcd6eb3687c158743cf",
        "0x0175496d8265dedd693cf88884626c33b699ebcf4f2110e4c7fb7603c53215b2",
        "0x11fb433ab551b33f30d00a34396835fab72e316e81d1e0afcbc92e79801f30c4",
        "0x060dc4541fd534d107f6e49b96d84f5ec6dbe4eb714890e800bd02399a6bfb7f",
        "0x01956de9f96f9a268c6524fffb9919d7fa3de7a4c25d53c2ccc43d0cb022a7ff",
        "0x15057378f2d223829269ec0f31ba4bb03146134220d34eb8eb7c403aa4a2e569",
        "0x16ea0218d72b5e3f69d0ae4daa8085150f5f7e69ee22a3b054744e35e2082879",
        "0x0baf4e8ff92058c1cac3b95c237edb4d2c12ad41d210356c209f1e0bf0d2d12a",
        "0x1a8ac77aff614caeca16a5a3a0931375a5a4fbe0ef1e15d6d15bf6f8e3c60f4f",
        "0xdb899136f41a3d4710907345b09d241490776383271e6b9887499fd05b80fcd4",
        "0x1007e17b1120d37fb930f953d8a3440ca11b8fd84470eb107c8b4a402a9813fd",
        "0x0910324706ffeebf8aa25ca0784636518bf67e5d173c22438a64dd43d5f4aa2a",
        "0x028f2bee56aee7005abcb2258d6d9f0f078a85a65c3d669aca40564ef4bd7f94",
        "0x14adac9bc94cde3166f4b7d42e8862a745483c708e51afbe89ecd6532acc532e",
        "0x54bed12ccad43523ba8527d1b99f5fa04a55b3a7724cfff2e0a21ec90b08590e",
        "0xcdf05df923f6e418505750069d6486276b15fcc3cd2f42a7044c642d19a86d51",
        "0x0c66977ed87db75074cb2bea66b254af3b20bb3315e8095290ceb1260b1b7449",
        "0x348cfc85c58b7f3b2e8bdaa517dc8e3c5f8fb41e3ba235f28892b46bc3484756",
        "0x4ac009cebc1f2416b9e39bcc5b41cd53b1a9239e8f6c0ab043b8830ef1ffc563",
        "0xf2a96682362b9ffe9a77190bcbc47937743b6e1da2c56257f9b562f15bbd3cfa",
        "0xf1cd627c97746bc75727c2f0efa2d0dc66cca1b36d8e45d897e18a9b19af2f60",
        "0x241d89f7888fbcfadfd415ee967882fec6fdd67c07ca8a00f2ca4c910a84c7dd"
        ],
        "transactionsRoot": "0xf98631e290e88f58a46b7032f025969039aa9b5696498efc76baf436fa69b262",
        "uncles": [
        "0x824cce7c7c2ec6874b9fa9a9a898eb5f27cbaf3991dfa81084c3af60d1db618c"
        ]
    }"#)?;

    module.register_method("eth_getBlockByNumber", move |_, _| Ok(block.clone())).unwrap();
    methods.merge(module)?;

    *runtime.jrpc_handle.lock().unwrap() = Some(server.start(methods)?);
    Ok(())
}

pub fn add_grpc_server(runtime: &Runtime, addr: &str) -> Result<(), Box<dyn Error>> {
    log::info!("Starting gRPC server at {}", addr);
    runtime.rt_handle.spawn(
        Server::builder()
            .add_service(BlockchainService::new(Arc::clone(&runtime.handlers)).service())
            .add_service(EthService::new(Arc::clone(&runtime.handlers)).service())
            .serve(addr.parse()?),
    );
    Ok(())
}

pub fn init_runtime() {
    log::info!("Starting gRPC and JSON RPC servers");
    LogBuilder::from_env(Env::default().default_filter_or(Level::Info.as_str())).init();
    let _ = &*RUNTIME;
}

pub fn start_servers(json_addr: &str, grpc_addr: &str) -> Result<(), Box<dyn Error>> {
    add_json_rpc_server(&RUNTIME, json_addr)?;
    add_grpc_server(&RUNTIME, grpc_addr)?;
    Ok(())
}

pub fn stop_runtime() {
    log::info!("Stopping gRPC and JSON RPC servers");
    RUNTIME.stop();
}
