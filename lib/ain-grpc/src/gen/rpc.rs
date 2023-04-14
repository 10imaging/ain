/// Generated server implementations.
pub mod blockchain_server {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Generated trait containing gRPC methods that should be implemented for use with BlockchainServer.
    #[async_trait]
    pub trait Blockchain: Send + Sync + 'static {
        /// [ignore]
        /// Returns the hash of the best (tip) block in the most-work fully-validated chain.
        async fn get_best_block_hash(
            &self,
            request: tonic::Request<()>,
        ) -> Result<
            tonic::Response<super::super::types::BlockHashResult>,
            tonic::Status,
        >;
        /// [ignore]
        async fn get_block(
            &self,
            request: tonic::Request<super::super::types::BlockInput>,
        ) -> Result<tonic::Response<super::super::types::BlockResult>, tonic::Status>;
    }
    #[derive(Debug)]
    pub struct BlockchainServer<T: Blockchain> {
        inner: _Inner<T>,
        accept_compression_encodings: EnabledCompressionEncodings,
        send_compression_encodings: EnabledCompressionEncodings,
    }
    struct _Inner<T>(Arc<T>);
    impl<T: Blockchain> BlockchainServer<T> {
        pub fn new(inner: T) -> Self {
            Self::from_arc(Arc::new(inner))
        }
        pub fn from_arc(inner: Arc<T>) -> Self {
            let inner = _Inner(inner);
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
            }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
        /// Enable decompressing requests with the given encoding.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.accept_compression_encodings.enable(encoding);
            self
        }
        /// Compress responses with the given encoding, if the client supports it.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.send_compression_encodings.enable(encoding);
            self
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>> for BlockchainServer<T>
    where
        T: Blockchain,
        B: Body + Send + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/rpc.Blockchain/GetBestBlockHash" => {
                    #[allow(non_camel_case_types)]
                    struct GetBestBlockHashSvc<T: Blockchain>(pub Arc<T>);
                    impl<T: Blockchain> tonic::server::UnaryService<()>
                    for GetBestBlockHashSvc<T> {
                        type Response = super::super::types::BlockHashResult;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(&mut self, request: tonic::Request<()>) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move {
                                (*inner).get_best_block_hash(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = GetBestBlockHashSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/rpc.Blockchain/GetBlock" => {
                    #[allow(non_camel_case_types)]
                    struct GetBlockSvc<T: Blockchain>(pub Arc<T>);
                    impl<
                        T: Blockchain,
                    > tonic::server::UnaryService<super::super::types::BlockInput>
                    for GetBlockSvc<T> {
                        type Response = super::super::types::BlockResult;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::super::types::BlockInput>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).get_block(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = GetBlockSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => {
                    Box::pin(async move {
                        Ok(
                            http::Response::builder()
                                .status(200)
                                .header("grpc-status", "12")
                                .header("content-type", "application/grpc")
                                .body(empty_body())
                                .unwrap(),
                        )
                    })
                }
            }
        }
    }
    impl<T: Blockchain> Clone for BlockchainServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
            }
        }
    }
    impl<T: Blockchain> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone())
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: Blockchain> tonic::server::NamedService for BlockchainServer<T> {
        const NAME: &'static str = "rpc.Blockchain";
    }
}
/// Generated server implementations.
pub mod eth_server {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Generated trait containing gRPC methods that should be implemented for use with EthServer.
    #[async_trait]
    pub trait Eth: Send + Sync + 'static {
        /// / Returns eth_accounts list.
        async fn eth_accounts(
            &self,
            request: tonic::Request<()>,
        ) -> Result<
            tonic::Response<super::super::types::EthAccountsResult>,
            tonic::Status,
        >;
        /// / Call contract, returning the output data. Does not create a transaction.
        async fn eth_call(
            &self,
            request: tonic::Request<super::super::types::EthCallInput>,
        ) -> Result<tonic::Response<super::super::types::EthCallResult>, tonic::Status>;
        /// / Returns the balance for the given address.
        async fn eth_get_balance(
            &self,
            request: tonic::Request<super::super::types::EthGetBalanceInput>,
        ) -> Result<
            tonic::Response<super::super::types::EthGetBalanceResult>,
            tonic::Status,
        >;
        async fn eth_get_block_by_hash(
            &self,
            request: tonic::Request<super::super::types::EthGetBlockByHashInput>,
        ) -> Result<tonic::Response<super::super::types::EthBlockInfo>, tonic::Status>;
        /// / [ignore]
        /// / Returns the balance for the given address.
        async fn eth_send_transaction(
            &self,
            request: tonic::Request<super::super::types::EthSendTransactionInput>,
        ) -> Result<
            tonic::Response<super::super::types::EthSendTransactionResult>,
            tonic::Status,
        >;
        async fn eth_chain_id(
            &self,
            request: tonic::Request<()>,
        ) -> Result<
            tonic::Response<super::super::types::EthChainIdResult>,
            tonic::Status,
        >;
        async fn net_version(
            &self,
            request: tonic::Request<()>,
        ) -> Result<
            tonic::Response<super::super::types::EthChainIdResult>,
            tonic::Status,
        >;
        async fn eth_block_number(
            &self,
            request: tonic::Request<()>,
        ) -> Result<
            tonic::Response<super::super::types::EthBlockNumberResult>,
            tonic::Status,
        >;
        async fn eth_get_block_by_number(
            &self,
            request: tonic::Request<super::super::types::EthGetBlockByNumberInput>,
        ) -> Result<tonic::Response<super::super::types::EthBlockInfo>, tonic::Status>;
        /// / Returns the information about a transaction from a transaction hash.
        async fn eth_get_transaction_by_hash(
            &self,
            request: tonic::Request<super::super::types::EthGetTransactionByHashInput>,
        ) -> Result<
            tonic::Response<super::super::types::EthTransactionInfo>,
            tonic::Status,
        >;
        /// / Returns information about a transaction given a blockhash and transaction index position.
        async fn eth_get_transaction_by_block_hash_and_index(
            &self,
            request: tonic::Request<
                super::super::types::EthGetTransactionByBlockHashAndIndexInput,
            >,
        ) -> Result<
            tonic::Response<super::super::types::EthTransactionInfo>,
            tonic::Status,
        >;
        /// / Returns information about a transaction given a block number and transaction index position.
        async fn eth_get_transaction_by_block_number_and_index(
            &self,
            request: tonic::Request<
                super::super::types::EthGetTransactionByBlockNumberAndIndexInput,
            >,
        ) -> Result<
            tonic::Response<super::super::types::EthTransactionInfo>,
            tonic::Status,
        >;
        async fn eth_mining(
            &self,
            request: tonic::Request<()>,
        ) -> Result<
            tonic::Response<super::super::types::EthMiningResult>,
            tonic::Status,
        >;
        async fn eth_get_block_transaction_count_by_hash(
            &self,
            request: tonic::Request<
                super::super::types::EthGetBlockTransactionCountByHashInput,
            >,
        ) -> Result<
            tonic::Response<
                super::super::types::EthGetBlockTransactionCountByHashResult,
            >,
            tonic::Status,
        >;
        async fn eth_get_block_transaction_count_by_number(
            &self,
            request: tonic::Request<
                super::super::types::EthGetBlockTransactionCountByNumberInput,
            >,
        ) -> Result<
            tonic::Response<
                super::super::types::EthGetBlockTransactionCountByNumberResult,
            >,
            tonic::Status,
        >;
        async fn eth_get_code(
            &self,
            request: tonic::Request<super::super::types::EthGetCodeInput>,
        ) -> Result<
            tonic::Response<super::super::types::EthGetCodeResult>,
            tonic::Status,
        >;
        async fn eth_get_storage_at(
            &self,
            request: tonic::Request<super::super::types::EthGetStorageAtInput>,
        ) -> Result<
            tonic::Response<super::super::types::EthGetStorageAtResult>,
            tonic::Status,
        >;
    }
    #[derive(Debug)]
    pub struct EthServer<T: Eth> {
        inner: _Inner<T>,
        accept_compression_encodings: EnabledCompressionEncodings,
        send_compression_encodings: EnabledCompressionEncodings,
    }
    struct _Inner<T>(Arc<T>);
    impl<T: Eth> EthServer<T> {
        pub fn new(inner: T) -> Self {
            Self::from_arc(Arc::new(inner))
        }
        pub fn from_arc(inner: Arc<T>) -> Self {
            let inner = _Inner(inner);
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
            }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
        /// Enable decompressing requests with the given encoding.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.accept_compression_encodings.enable(encoding);
            self
        }
        /// Compress responses with the given encoding, if the client supports it.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.send_compression_encodings.enable(encoding);
            self
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>> for EthServer<T>
    where
        T: Eth,
        B: Body + Send + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/rpc.eth/Eth_Accounts" => {
                    #[allow(non_camel_case_types)]
                    struct Eth_AccountsSvc<T: Eth>(pub Arc<T>);
                    impl<T: Eth> tonic::server::UnaryService<()> for Eth_AccountsSvc<T> {
                        type Response = super::super::types::EthAccountsResult;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(&mut self, request: tonic::Request<()>) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move {
                                (*inner).eth_accounts(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = Eth_AccountsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/rpc.eth/Eth_Call" => {
                    #[allow(non_camel_case_types)]
                    struct Eth_CallSvc<T: Eth>(pub Arc<T>);
                    impl<
                        T: Eth,
                    > tonic::server::UnaryService<super::super::types::EthCallInput>
                    for Eth_CallSvc<T> {
                        type Response = super::super::types::EthCallResult;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::super::types::EthCallInput>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).eth_call(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = Eth_CallSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/rpc.eth/Eth_GetBalance" => {
                    #[allow(non_camel_case_types)]
                    struct Eth_GetBalanceSvc<T: Eth>(pub Arc<T>);
                    impl<
                        T: Eth,
                    > tonic::server::UnaryService<
                        super::super::types::EthGetBalanceInput,
                    > for Eth_GetBalanceSvc<T> {
                        type Response = super::super::types::EthGetBalanceResult;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<
                                super::super::types::EthGetBalanceInput,
                            >,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move {
                                (*inner).eth_get_balance(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = Eth_GetBalanceSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/rpc.eth/Eth_GetBlockByHash" => {
                    #[allow(non_camel_case_types)]
                    struct Eth_GetBlockByHashSvc<T: Eth>(pub Arc<T>);
                    impl<
                        T: Eth,
                    > tonic::server::UnaryService<
                        super::super::types::EthGetBlockByHashInput,
                    > for Eth_GetBlockByHashSvc<T> {
                        type Response = super::super::types::EthBlockInfo;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<
                                super::super::types::EthGetBlockByHashInput,
                            >,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move {
                                (*inner).eth_get_block_by_hash(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = Eth_GetBlockByHashSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/rpc.eth/Eth_SendTransaction" => {
                    #[allow(non_camel_case_types)]
                    struct Eth_SendTransactionSvc<T: Eth>(pub Arc<T>);
                    impl<
                        T: Eth,
                    > tonic::server::UnaryService<
                        super::super::types::EthSendTransactionInput,
                    > for Eth_SendTransactionSvc<T> {
                        type Response = super::super::types::EthSendTransactionResult;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<
                                super::super::types::EthSendTransactionInput,
                            >,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move {
                                (*inner).eth_send_transaction(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = Eth_SendTransactionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/rpc.eth/Eth_ChainId" => {
                    #[allow(non_camel_case_types)]
                    struct Eth_ChainIdSvc<T: Eth>(pub Arc<T>);
                    impl<T: Eth> tonic::server::UnaryService<()> for Eth_ChainIdSvc<T> {
                        type Response = super::super::types::EthChainIdResult;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(&mut self, request: tonic::Request<()>) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move {
                                (*inner).eth_chain_id(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = Eth_ChainIdSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/rpc.eth/Net_Version" => {
                    #[allow(non_camel_case_types)]
                    struct Net_VersionSvc<T: Eth>(pub Arc<T>);
                    impl<T: Eth> tonic::server::UnaryService<()> for Net_VersionSvc<T> {
                        type Response = super::super::types::EthChainIdResult;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(&mut self, request: tonic::Request<()>) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).net_version(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = Net_VersionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/rpc.eth/Eth_BlockNumber" => {
                    #[allow(non_camel_case_types)]
                    struct Eth_BlockNumberSvc<T: Eth>(pub Arc<T>);
                    impl<T: Eth> tonic::server::UnaryService<()>
                    for Eth_BlockNumberSvc<T> {
                        type Response = super::super::types::EthBlockNumberResult;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(&mut self, request: tonic::Request<()>) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move {
                                (*inner).eth_block_number(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = Eth_BlockNumberSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/rpc.eth/Eth_GetBlockByNumber" => {
                    #[allow(non_camel_case_types)]
                    struct Eth_GetBlockByNumberSvc<T: Eth>(pub Arc<T>);
                    impl<
                        T: Eth,
                    > tonic::server::UnaryService<
                        super::super::types::EthGetBlockByNumberInput,
                    > for Eth_GetBlockByNumberSvc<T> {
                        type Response = super::super::types::EthBlockInfo;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<
                                super::super::types::EthGetBlockByNumberInput,
                            >,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move {
                                (*inner).eth_get_block_by_number(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = Eth_GetBlockByNumberSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/rpc.eth/Eth_GetTransactionByHash" => {
                    #[allow(non_camel_case_types)]
                    struct Eth_GetTransactionByHashSvc<T: Eth>(pub Arc<T>);
                    impl<
                        T: Eth,
                    > tonic::server::UnaryService<
                        super::super::types::EthGetTransactionByHashInput,
                    > for Eth_GetTransactionByHashSvc<T> {
                        type Response = super::super::types::EthTransactionInfo;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<
                                super::super::types::EthGetTransactionByHashInput,
                            >,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move {
                                (*inner).eth_get_transaction_by_hash(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = Eth_GetTransactionByHashSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/rpc.eth/Eth_GetTransactionByBlockHashAndIndex" => {
                    #[allow(non_camel_case_types)]
                    struct Eth_GetTransactionByBlockHashAndIndexSvc<T: Eth>(pub Arc<T>);
                    impl<
                        T: Eth,
                    > tonic::server::UnaryService<
                        super::super::types::EthGetTransactionByBlockHashAndIndexInput,
                    > for Eth_GetTransactionByBlockHashAndIndexSvc<T> {
                        type Response = super::super::types::EthTransactionInfo;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<
                                super::super::types::EthGetTransactionByBlockHashAndIndexInput,
                            >,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move {
                                (*inner)
                                    .eth_get_transaction_by_block_hash_and_index(request)
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = Eth_GetTransactionByBlockHashAndIndexSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/rpc.eth/Eth_GetTransactionByBlockNumberAndIndex" => {
                    #[allow(non_camel_case_types)]
                    struct Eth_GetTransactionByBlockNumberAndIndexSvc<T: Eth>(
                        pub Arc<T>,
                    );
                    impl<
                        T: Eth,
                    > tonic::server::UnaryService<
                        super::super::types::EthGetTransactionByBlockNumberAndIndexInput,
                    > for Eth_GetTransactionByBlockNumberAndIndexSvc<T> {
                        type Response = super::super::types::EthTransactionInfo;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<
                                super::super::types::EthGetTransactionByBlockNumberAndIndexInput,
                            >,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move {
                                (*inner)
                                    .eth_get_transaction_by_block_number_and_index(request)
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = Eth_GetTransactionByBlockNumberAndIndexSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/rpc.eth/Eth_Mining" => {
                    #[allow(non_camel_case_types)]
                    struct Eth_MiningSvc<T: Eth>(pub Arc<T>);
                    impl<T: Eth> tonic::server::UnaryService<()> for Eth_MiningSvc<T> {
                        type Response = super::super::types::EthMiningResult;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(&mut self, request: tonic::Request<()>) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).eth_mining(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = Eth_MiningSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/rpc.eth/Eth_GetBlockTransactionCountByHash" => {
                    #[allow(non_camel_case_types)]
                    struct Eth_GetBlockTransactionCountByHashSvc<T: Eth>(pub Arc<T>);
                    impl<
                        T: Eth,
                    > tonic::server::UnaryService<
                        super::super::types::EthGetBlockTransactionCountByHashInput,
                    > for Eth_GetBlockTransactionCountByHashSvc<T> {
                        type Response = super::super::types::EthGetBlockTransactionCountByHashResult;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<
                                super::super::types::EthGetBlockTransactionCountByHashInput,
                            >,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move {
                                (*inner)
                                    .eth_get_block_transaction_count_by_hash(request)
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = Eth_GetBlockTransactionCountByHashSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/rpc.eth/Eth_GetBlockTransactionCountByNumber" => {
                    #[allow(non_camel_case_types)]
                    struct Eth_GetBlockTransactionCountByNumberSvc<T: Eth>(pub Arc<T>);
                    impl<
                        T: Eth,
                    > tonic::server::UnaryService<
                        super::super::types::EthGetBlockTransactionCountByNumberInput,
                    > for Eth_GetBlockTransactionCountByNumberSvc<T> {
                        type Response = super::super::types::EthGetBlockTransactionCountByNumberResult;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<
                                super::super::types::EthGetBlockTransactionCountByNumberInput,
                            >,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move {
                                (*inner)
                                    .eth_get_block_transaction_count_by_number(request)
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = Eth_GetBlockTransactionCountByNumberSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/rpc.eth/Eth_GetCode" => {
                    #[allow(non_camel_case_types)]
                    struct Eth_GetCodeSvc<T: Eth>(pub Arc<T>);
                    impl<
                        T: Eth,
                    > tonic::server::UnaryService<super::super::types::EthGetCodeInput>
                    for Eth_GetCodeSvc<T> {
                        type Response = super::super::types::EthGetCodeResult;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::super::types::EthGetCodeInput>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move {
                                (*inner).eth_get_code(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = Eth_GetCodeSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/rpc.eth/Eth_GetStorageAt" => {
                    #[allow(non_camel_case_types)]
                    struct Eth_GetStorageAtSvc<T: Eth>(pub Arc<T>);
                    impl<
                        T: Eth,
                    > tonic::server::UnaryService<
                        super::super::types::EthGetStorageAtInput,
                    > for Eth_GetStorageAtSvc<T> {
                        type Response = super::super::types::EthGetStorageAtResult;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<
                                super::super::types::EthGetStorageAtInput,
                            >,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move {
                                (*inner).eth_get_storage_at(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = Eth_GetStorageAtSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => {
                    Box::pin(async move {
                        Ok(
                            http::Response::builder()
                                .status(200)
                                .header("grpc-status", "12")
                                .header("content-type", "application/grpc")
                                .body(empty_body())
                                .unwrap(),
                        )
                    })
                }
            }
        }
    }
    impl<T: Eth> Clone for EthServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
            }
        }
    }
    impl<T: Eth> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone())
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: Eth> tonic::server::NamedService for EthServer<T> {
        const NAME: &'static str = "rpc.eth";
    }
}

#[cxx::bridge]
pub mod ffi {
# [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct Transaction { pub hash : String , pub raw : RawTransaction , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct RawTransaction { pub in_active_chain : bool , pub hex : String , pub txid : String , pub hash : String , pub size : u32 , pub vsize : u32 , pub weight : u32 , pub version : u32 , pub locktime : u64 , pub vin : Vec < Vin > , pub vout : Vec < Vout > , pub blockhash : String , pub confirmations : String , pub blocktime : u64 , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct Vin { pub txid : String , pub vout : u32 , pub script_sig : ScriptSig , pub sequence : u64 , pub txinwitness : Vec < String > , pub coinbase : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct ScriptSig { pub field_asm : String , pub hex : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct Vout { pub value : f64 , pub n : u64 , pub script_pub_key : PubKey , pub token_id : u64 , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct PubKey { pub field_asm : String , pub hex : String , pub field_type : String , pub req_sigs : i32 , pub addresses : Vec < String > , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthAccountsResult { pub accounts : Vec < String > , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthTransactionInfo { pub from : String , pub to : String , pub gas : u64 , pub price : String , pub value : String , pub data : String , pub nonce : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthChainIdResult { pub id : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthBlockInfo { pub block_number : String , pub hash : String , pub parent_hash : String , pub nonce : String , pub sha3_uncles : String , pub logs_bloom : String , pub transactions_root : String , pub state_root : String , pub receipt_root : String , pub miner : String , pub difficulty : String , pub total_difficulty : String , pub extra_data : String , pub size : String , pub gas_limit : String , pub gas_used : String , pub timestamps : String , pub transactions : Vec < String > , pub uncles : Vec < String > , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthTransactionReceipt { pub transaction_hash : String , pub transaction_index : String , pub block_hash : String , pub block_number : String , pub from : String , pub to : String , pub cumulative_gas_used : String , pub effective_gas_price : String , pub gas_used : String , pub contract_address : String , pub logs : Vec < String > , pub logs_bloom : String , pub field_type : String , pub root : String , pub status : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthCallInput { pub transaction_info : EthTransactionInfo , pub block_number : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthCallResult { pub data : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthSignInput { pub address : String , pub message : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthSignResult { pub signature : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetBalanceInput { pub address : String , pub block_number : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetBalanceResult { pub balance : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthSendTransactionInput { pub transaction_info : EthTransactionInfo , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthSendTransactionResult { pub hash : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthCoinBaseResult { pub address : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthMiningResult { pub is_mining : bool , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthHashRateResult { pub hash_rate : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGasPriceResult { pub gas_price : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthBlockNumberResult { pub block_number : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetTransactionCountInput { pub address : String , pub block_number : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetTransactionCountResult { pub number_transaction : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetBlockTransactionCountByHashInput { pub block_hash : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetBlockTransactionCountByHashResult { pub number_transaction : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetBlockTransactionCountByNumberInput { pub block_number : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetBlockTransactionCountByNumberResult { pub number_transaction : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetUncleCountByBlockHashInput { pub block_hash : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetUncleCountByBlockHashResult { pub number_uncles : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetUncleCountByBlockNumberInput { pub block_number : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetUncleCountByBlockNumberResult { pub number_uncles : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetCodeInput { pub address : String , pub block_number : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetCodeResult { pub code : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthSignTransactionInput { pub transaction_info : EthTransactionInfo , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthSignTransactionResult { pub transaction : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthSendRawTransactionInput { pub transaction : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthSendRawTransactionResult { pub hash : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthEstimateGasInput { pub transaction_info : EthTransactionInfo , pub block_number : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthEstimateGasResult { pub gas_used : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetBlockByHashInput { pub hash : String , pub full_transaction : bool , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetBlockByHashResult { pub block_info : EthBlockInfo , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetBlockByNumberInput { pub number : String , pub full_transaction : bool , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetBlockByNumberResult { pub block_info : EthBlockInfo , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetTransactionByHashInput { pub hash : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetTransactionByHashResult { pub transaction : EthTransactionInfo , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetTransactionByBlockHashAndIndexInput { pub block_hash : String , pub index : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetTransactionByBlockHashAndIndexResult { pub transaction : EthTransactionInfo , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetTransactionByBlockNumberAndIndexInput { pub block_number : String , pub index : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetTransactionByBlockNumberAndIndexResult { pub transaction : EthTransactionInfo , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetUncleByBlockHashAndIndexInput { pub block_hash : String , pub index : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetUncleByBlockHashAndIndexResult { pub block_info : EthBlockInfo , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetUncleByBlockNumberAndIndexInput { pub block_number : String , pub index : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetUncleByBlockNumberAndIndexResult { pub block_info : EthBlockInfo , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetCompilersResult { pub compilers : Vec < String > , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthCompileSolidityInput { pub code : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthCompileSolidityResult { pub compiled_code : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthCompileLllInput { pub code : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthCompileLllResult { pub compiled_code : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthCompileSerpentInput { pub code : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthCompileSerpentResult { pub compiled_code : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthProtocolVersionResult { pub protocol_version : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct Web3Sha3Input { pub data : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct Web3Sha3Result { pub data : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct NetPeerCountResult { pub number_peer : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct NetVersionResult { pub network_version : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct Web3ClientVersionResult { pub client_version : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetWorkResult { pub currentblock : String , pub seed_hash : String , pub target : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthSubmitWorkInput { pub nounce : String , pub pow_hash : String , pub mix_digest : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthSubmitWorkResult { pub is_valid : bool , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthSubmitHashrateInput { pub hash_rate : String , pub id : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthSubmitHashrateResult { pub is_valid : bool , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetStorageAtInput { pub address : String , pub position : String , pub block_number : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetStorageAtResult { pub value : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetTransactionReceiptInput { pub transaction_hash : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthGetTransactionReceiptResult { pub transaction_receipt : EthTransactionReceipt , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthSyncingInfo { pub starting_block : String , pub current_block : String , pub highest_block : String , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct EthSyncingResult { pub status : bool , pub sync_info : EthSyncingInfo , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct Block { pub hash : String , pub confirmations : i64 , pub size : u64 , pub strippedsize : u64 , pub weight : u64 , pub height : u64 , pub version : u64 , pub version_hex : String , pub merkleroot : String , pub tx : Vec < Transaction > , pub time : u64 , pub mediantime : u64 , pub nonce : u64 , pub bits : String , pub difficulty : f64 , pub chainwork : String , pub n_tx : u32 , pub previous_block_hash : String , pub next_block_hash : String , pub masternode : String , pub minter : String , pub minted_blocks : u64 , pub stake_modifier : String , pub nonutxo : Vec < NonUtxo > , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct NonUtxo { pub anchor_reward : f64 , pub burnt : f64 , pub incentive_funding : f64 , pub loan : f64 , pub options : f64 , pub unknown : f64 , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct BlockInput { pub blockhash : String , pub verbosity : u32 , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct BlockResult { pub hash : String , pub block : Block , } # [derive (Debug , Default , Serialize , Deserialize , PartialEq)] pub struct BlockHashResult { pub hash : String , } extern "Rust" { type Client ; fn NewClient (addr : & str) -> Result < Box < Client >> ; # [allow (clippy :: borrowed_box)] fn CallEth_Accounts (client : & Box < Client >) -> Result < EthAccountsResult > ; # [allow (clippy :: borrowed_box)] fn CallEth_Call (client : & Box < Client > , eth_call_input : EthCallInput) -> Result < EthCallResult > ; # [allow (clippy :: borrowed_box)] fn CallEth_GetBalance (client : & Box < Client > , eth_get_balance_input : EthGetBalanceInput) -> Result < EthGetBalanceResult > ; # [allow (clippy :: borrowed_box)] fn CallEth_GetBlockByHash (client : & Box < Client > , eth_get_block_by_hash_input : EthGetBlockByHashInput) -> Result < EthBlockInfo > ; # [allow (clippy :: borrowed_box)] fn CallEth_ChainId (client : & Box < Client >) -> Result < EthChainIdResult > ; # [allow (clippy :: borrowed_box)] fn CallNet_Version (client : & Box < Client >) -> Result < EthChainIdResult > ; # [allow (clippy :: borrowed_box)] fn CallEth_BlockNumber (client : & Box < Client >) -> Result < EthBlockNumberResult > ; # [allow (clippy :: borrowed_box)] fn CallEth_GetBlockByNumber (client : & Box < Client > , eth_get_block_by_number_input : EthGetBlockByNumberInput) -> Result < EthBlockInfo > ; # [allow (clippy :: borrowed_box)] fn CallEth_GetTransactionByHash (client : & Box < Client > , eth_get_transaction_by_hash_input : EthGetTransactionByHashInput) -> Result < EthTransactionInfo > ; # [allow (clippy :: borrowed_box)] fn CallEth_GetTransactionByBlockHashAndIndex (client : & Box < Client > , eth_get_transaction_by_block_hash_and_index_input : EthGetTransactionByBlockHashAndIndexInput) -> Result < EthTransactionInfo > ; # [allow (clippy :: borrowed_box)] fn CallEth_GetTransactionByBlockNumberAndIndex (client : & Box < Client > , eth_get_transaction_by_block_number_and_index_input : EthGetTransactionByBlockNumberAndIndexInput) -> Result < EthTransactionInfo > ; # [allow (clippy :: borrowed_box)] fn CallEth_Mining (client : & Box < Client >) -> Result < EthMiningResult > ; # [allow (clippy :: borrowed_box)] fn CallEth_GetBlockTransactionCountByHash (client : & Box < Client > , eth_get_block_transaction_count_by_hash_input : EthGetBlockTransactionCountByHashInput) -> Result < EthGetBlockTransactionCountByHashResult > ; # [allow (clippy :: borrowed_box)] fn CallEth_GetBlockTransactionCountByNumber (client : & Box < Client > , eth_get_block_transaction_count_by_number_input : EthGetBlockTransactionCountByNumberInput) -> Result < EthGetBlockTransactionCountByNumberResult > ; # [allow (clippy :: borrowed_box)] fn CallEth_GetCode (client : & Box < Client > , eth_get_code_input : EthGetCodeInput) -> Result < EthGetCodeResult > ; # [allow (clippy :: borrowed_box)] fn CallEth_GetStorageAt (client : & Box < Client > , eth_get_storage_at_input : EthGetStorageAtInput) -> Result < EthGetStorageAtResult > ; }
}
use jsonrpsee_core :: client :: ClientT ; use jsonrpsee_http_client :: { HttpClient , HttpClientBuilder } ; use std :: sync :: Arc ; use crate :: { CLIENTS } ; use ain_evm :: runtime :: RUNTIME ; use crate :: rpc :: * ; # [allow (unused_imports)] use self :: ffi :: * ; use ain_evm :: handler :: Handlers ; # [derive (Clone)] pub struct Client { inner : Arc < HttpClient > , handle : tokio :: runtime :: Handle , } # [allow (non_snake_case)] fn NewClient (addr : & str) -> Result < Box < Client > , Box < dyn std :: error :: Error >> { if CLIENTS . read () . unwrap () . get (addr) . is_none () { log :: info ! ("Initializing RPC client for {}" , addr) ; let c = Client { inner : Arc :: new (HttpClientBuilder :: default () . build (addr) ?) , handle : RUNTIME . rt_handle . clone () , } ; CLIENTS . write () . unwrap () . insert (addr . into () , c) ; } Ok (Box :: new (CLIENTS . read () . unwrap () . get (addr) . unwrap () . clone ())) } # [allow (dead_code)] fn missing_param (field : & str) -> jsonrpsee_core :: Error { jsonrpsee_core :: Error :: Call (jsonrpsee_types :: error :: CallError :: Custom (jsonrpsee_types :: ErrorObject :: borrowed (- 1 , & format ! ("Missing required parameter '{field}'") , None) . into_owned ())) } impl From < ffi :: EthGetTransactionByBlockHashAndIndexResult > for super :: types :: EthGetTransactionByBlockHashAndIndexResult { fn from (other : ffi :: EthGetTransactionByBlockHashAndIndexResult) -> Self { super :: types :: EthGetTransactionByBlockHashAndIndexResult { transaction : Some (other . transaction . into ()) , } } } impl From < super :: types :: EthGetTransactionByBlockHashAndIndexResult > for ffi :: EthGetTransactionByBlockHashAndIndexResult { fn from (other : super :: types :: EthGetTransactionByBlockHashAndIndexResult) -> Self { ffi :: EthGetTransactionByBlockHashAndIndexResult { transaction : other . transaction . map (Into :: into) . unwrap_or_default () , } } } impl From < ffi :: EthGetCodeInput > for super :: types :: EthGetCodeInput { fn from (other : ffi :: EthGetCodeInput) -> Self { super :: types :: EthGetCodeInput { address : other . address . into () , block_number : other . block_number . into () , } } } impl From < super :: types :: EthGetCodeInput > for ffi :: EthGetCodeInput { fn from (other : super :: types :: EthGetCodeInput) -> Self { ffi :: EthGetCodeInput { address : other . address . into () , block_number : other . block_number . into () , } } } impl From < ffi :: Transaction > for super :: types :: Transaction { fn from (other : ffi :: Transaction) -> Self { super :: types :: Transaction { hash : other . hash . into () , raw : Some (other . raw . into ()) , } } } impl From < super :: types :: Transaction > for ffi :: Transaction { fn from (other : super :: types :: Transaction) -> Self { ffi :: Transaction { hash : other . hash . into () , raw : other . raw . map (Into :: into) . unwrap_or_default () , } } } impl From < ffi :: EthSignInput > for super :: types :: EthSignInput { fn from (other : ffi :: EthSignInput) -> Self { super :: types :: EthSignInput { address : other . address . into () , message : other . message . into () , } } } impl From < super :: types :: EthSignInput > for ffi :: EthSignInput { fn from (other : super :: types :: EthSignInput) -> Self { ffi :: EthSignInput { address : other . address . into () , message : other . message . into () , } } } impl From < ffi :: EthCompileSerpentResult > for super :: types :: EthCompileSerpentResult { fn from (other : ffi :: EthCompileSerpentResult) -> Self { super :: types :: EthCompileSerpentResult { compiled_code : other . compiled_code . into () , } } } impl From < super :: types :: EthCompileSerpentResult > for ffi :: EthCompileSerpentResult { fn from (other : super :: types :: EthCompileSerpentResult) -> Self { ffi :: EthCompileSerpentResult { compiled_code : other . compiled_code . into () , } } } impl From < ffi :: Web3ClientVersionResult > for super :: types :: Web3ClientVersionResult { fn from (other : ffi :: Web3ClientVersionResult) -> Self { super :: types :: Web3ClientVersionResult { client_version : other . client_version . into () , } } } impl From < super :: types :: Web3ClientVersionResult > for ffi :: Web3ClientVersionResult { fn from (other : super :: types :: Web3ClientVersionResult) -> Self { ffi :: Web3ClientVersionResult { client_version : other . client_version . into () , } } } impl From < ffi :: EthGetStorageAtResult > for super :: types :: EthGetStorageAtResult { fn from (other : ffi :: EthGetStorageAtResult) -> Self { super :: types :: EthGetStorageAtResult { value : other . value . into () , } } } impl From < super :: types :: EthGetStorageAtResult > for ffi :: EthGetStorageAtResult { fn from (other : super :: types :: EthGetStorageAtResult) -> Self { ffi :: EthGetStorageAtResult { value : other . value . into () , } } } impl From < ffi :: Vout > for super :: types :: Vout { fn from (other : ffi :: Vout) -> Self { super :: types :: Vout { value : other . value . into () , n : other . n . into () , script_pub_key : Some (other . script_pub_key . into ()) , token_id : other . token_id . into () , } } } impl From < super :: types :: Vout > for ffi :: Vout { fn from (other : super :: types :: Vout) -> Self { ffi :: Vout { value : other . value . into () , n : other . n . into () , script_pub_key : other . script_pub_key . map (Into :: into) . unwrap_or_default () , token_id : other . token_id . into () , } } } impl From < ffi :: EthCompileSerpentInput > for super :: types :: EthCompileSerpentInput { fn from (other : ffi :: EthCompileSerpentInput) -> Self { super :: types :: EthCompileSerpentInput { code : other . code . into () , } } } impl From < super :: types :: EthCompileSerpentInput > for ffi :: EthCompileSerpentInput { fn from (other : super :: types :: EthCompileSerpentInput) -> Self { ffi :: EthCompileSerpentInput { code : other . code . into () , } } } impl From < ffi :: EthGetUncleByBlockNumberAndIndexResult > for super :: types :: EthGetUncleByBlockNumberAndIndexResult { fn from (other : ffi :: EthGetUncleByBlockNumberAndIndexResult) -> Self { super :: types :: EthGetUncleByBlockNumberAndIndexResult { block_info : Some (other . block_info . into ()) , } } } impl From < super :: types :: EthGetUncleByBlockNumberAndIndexResult > for ffi :: EthGetUncleByBlockNumberAndIndexResult { fn from (other : super :: types :: EthGetUncleByBlockNumberAndIndexResult) -> Self { ffi :: EthGetUncleByBlockNumberAndIndexResult { block_info : other . block_info . map (Into :: into) . unwrap_or_default () , } } } impl From < ffi :: EthGetUncleByBlockHashAndIndexInput > for super :: types :: EthGetUncleByBlockHashAndIndexInput { fn from (other : ffi :: EthGetUncleByBlockHashAndIndexInput) -> Self { super :: types :: EthGetUncleByBlockHashAndIndexInput { block_hash : other . block_hash . into () , index : other . index . into () , } } } impl From < super :: types :: EthGetUncleByBlockHashAndIndexInput > for ffi :: EthGetUncleByBlockHashAndIndexInput { fn from (other : super :: types :: EthGetUncleByBlockHashAndIndexInput) -> Self { ffi :: EthGetUncleByBlockHashAndIndexInput { block_hash : other . block_hash . into () , index : other . index . into () , } } } impl From < ffi :: EthGetUncleByBlockNumberAndIndexInput > for super :: types :: EthGetUncleByBlockNumberAndIndexInput { fn from (other : ffi :: EthGetUncleByBlockNumberAndIndexInput) -> Self { super :: types :: EthGetUncleByBlockNumberAndIndexInput { block_number : other . block_number . into () , index : other . index . into () , } } } impl From < super :: types :: EthGetUncleByBlockNumberAndIndexInput > for ffi :: EthGetUncleByBlockNumberAndIndexInput { fn from (other : super :: types :: EthGetUncleByBlockNumberAndIndexInput) -> Self { ffi :: EthGetUncleByBlockNumberAndIndexInput { block_number : other . block_number . into () , index : other . index . into () , } } } impl From < ffi :: EthChainIdResult > for super :: types :: EthChainIdResult { fn from (other : ffi :: EthChainIdResult) -> Self { super :: types :: EthChainIdResult { id : other . id . into () , } } } impl From < super :: types :: EthChainIdResult > for ffi :: EthChainIdResult { fn from (other : super :: types :: EthChainIdResult) -> Self { ffi :: EthChainIdResult { id : other . id . into () , } } } impl From < ffi :: EthGetBlockTransactionCountByNumberResult > for super :: types :: EthGetBlockTransactionCountByNumberResult { fn from (other : ffi :: EthGetBlockTransactionCountByNumberResult) -> Self { super :: types :: EthGetBlockTransactionCountByNumberResult { number_transaction : other . number_transaction . into () , } } } impl From < super :: types :: EthGetBlockTransactionCountByNumberResult > for ffi :: EthGetBlockTransactionCountByNumberResult { fn from (other : super :: types :: EthGetBlockTransactionCountByNumberResult) -> Self { ffi :: EthGetBlockTransactionCountByNumberResult { number_transaction : other . number_transaction . into () , } } } impl From < ffi :: BlockResult > for super :: types :: BlockResult { fn from (other : ffi :: BlockResult) -> Self { super :: types :: BlockResult { hash : other . hash . into () , block : Some (other . block . into ()) , } } } impl From < super :: types :: BlockResult > for ffi :: BlockResult { fn from (other : super :: types :: BlockResult) -> Self { ffi :: BlockResult { hash : other . hash . into () , block : other . block . map (Into :: into) . unwrap_or_default () , } } } impl From < ffi :: EthEstimateGasInput > for super :: types :: EthEstimateGasInput { fn from (other : ffi :: EthEstimateGasInput) -> Self { super :: types :: EthEstimateGasInput { transaction_info : Some (other . transaction_info . into ()) , block_number : Some (other . block_number . into ()) , } } } impl From < super :: types :: EthEstimateGasInput > for ffi :: EthEstimateGasInput { fn from (other : super :: types :: EthEstimateGasInput) -> Self { ffi :: EthEstimateGasInput { transaction_info : other . transaction_info . map (Into :: into) . unwrap_or_default () , block_number : other . block_number . map (Into :: into) . unwrap_or_default () , } } } impl From < ffi :: EthCallResult > for super :: types :: EthCallResult { fn from (other : ffi :: EthCallResult) -> Self { super :: types :: EthCallResult { data : other . data . into () , } } } impl From < super :: types :: EthCallResult > for ffi :: EthCallResult { fn from (other : super :: types :: EthCallResult) -> Self { ffi :: EthCallResult { data : other . data . into () , } } } impl From < ffi :: EthGetCompilersResult > for super :: types :: EthGetCompilersResult { fn from (other : ffi :: EthGetCompilersResult) -> Self { super :: types :: EthGetCompilersResult { compilers : other . compilers . into_iter () . map (Into :: into) . collect () , } } } impl From < super :: types :: EthGetCompilersResult > for ffi :: EthGetCompilersResult { fn from (other : super :: types :: EthGetCompilersResult) -> Self { ffi :: EthGetCompilersResult { compilers : other . compilers . into_iter () . map (Into :: into) . collect () , } } } impl From < ffi :: PubKey > for super :: types :: PubKey { fn from (other : ffi :: PubKey) -> Self { super :: types :: PubKey { field_asm : other . field_asm . into () , hex : other . hex . into () , field_type : other . field_type . into () , req_sigs : other . req_sigs . into () , addresses : other . addresses . into_iter () . map (Into :: into) . collect () , } } } impl From < super :: types :: PubKey > for ffi :: PubKey { fn from (other : super :: types :: PubKey) -> Self { ffi :: PubKey { field_asm : other . field_asm . into () , hex : other . hex . into () , field_type : other . field_type . into () , req_sigs : other . req_sigs . into () , addresses : other . addresses . into_iter () . map (Into :: into) . collect () , } } } impl From < ffi :: EthSendTransactionInput > for super :: types :: EthSendTransactionInput { fn from (other : ffi :: EthSendTransactionInput) -> Self { super :: types :: EthSendTransactionInput { transaction_info : Some (other . transaction_info . into ()) , } } } impl From < super :: types :: EthSendTransactionInput > for ffi :: EthSendTransactionInput { fn from (other : super :: types :: EthSendTransactionInput) -> Self { ffi :: EthSendTransactionInput { transaction_info : other . transaction_info . map (Into :: into) . unwrap_or_default () , } } } impl From < ffi :: EthSendRawTransactionResult > for super :: types :: EthSendRawTransactionResult { fn from (other : ffi :: EthSendRawTransactionResult) -> Self { super :: types :: EthSendRawTransactionResult { hash : other . hash . into () , } } } impl From < super :: types :: EthSendRawTransactionResult > for ffi :: EthSendRawTransactionResult { fn from (other : super :: types :: EthSendRawTransactionResult) -> Self { ffi :: EthSendRawTransactionResult { hash : other . hash . into () , } } } impl From < ffi :: RawTransaction > for super :: types :: RawTransaction { fn from (other : ffi :: RawTransaction) -> Self { super :: types :: RawTransaction { in_active_chain : other . in_active_chain . into () , hex : other . hex . into () , txid : other . txid . into () , hash : other . hash . into () , size : other . size . into () , vsize : other . vsize . into () , weight : other . weight . into () , version : other . version . into () , locktime : other . locktime . into () , vin : other . vin . into_iter () . map (Into :: into) . collect () , vout : other . vout . into_iter () . map (Into :: into) . collect () , blockhash : other . blockhash . into () , confirmations : other . confirmations . into () , blocktime : other . blocktime . into () , } } } impl From < super :: types :: RawTransaction > for ffi :: RawTransaction { fn from (other : super :: types :: RawTransaction) -> Self { ffi :: RawTransaction { in_active_chain : other . in_active_chain . into () , hex : other . hex . into () , txid : other . txid . into () , hash : other . hash . into () , size : other . size . into () , vsize : other . vsize . into () , weight : other . weight . into () , version : other . version . into () , locktime : other . locktime . into () , vin : other . vin . into_iter () . map (Into :: into) . collect () , vout : other . vout . into_iter () . map (Into :: into) . collect () , blockhash : other . blockhash . into () , confirmations : other . confirmations . into () , blocktime : other . blocktime . into () , } } } impl From < ffi :: EthCallInput > for super :: types :: EthCallInput { fn from (other : ffi :: EthCallInput) -> Self { super :: types :: EthCallInput { transaction_info : Some (other . transaction_info . into ()) , block_number : other . block_number . into () , } } } impl From < super :: types :: EthCallInput > for ffi :: EthCallInput { fn from (other : super :: types :: EthCallInput) -> Self { ffi :: EthCallInput { transaction_info : other . transaction_info . map (Into :: into) . unwrap_or_default () , block_number : other . block_number . into () , } } } impl From < ffi :: Vin > for super :: types :: Vin { fn from (other : ffi :: Vin) -> Self { super :: types :: Vin { txid : other . txid . into () , vout : other . vout . into () , script_sig : Some (other . script_sig . into ()) , sequence : other . sequence . into () , txinwitness : other . txinwitness . into_iter () . map (Into :: into) . collect () , coinbase : other . coinbase . into () , } } } impl From < super :: types :: Vin > for ffi :: Vin { fn from (other : super :: types :: Vin) -> Self { ffi :: Vin { txid : other . txid . into () , vout : other . vout . into () , script_sig : other . script_sig . map (Into :: into) . unwrap_or_default () , sequence : other . sequence . into () , txinwitness : other . txinwitness . into_iter () . map (Into :: into) . collect () , coinbase : other . coinbase . into () , } } } impl From < ffi :: EthSubmitWorkResult > for super :: types :: EthSubmitWorkResult { fn from (other : ffi :: EthSubmitWorkResult) -> Self { super :: types :: EthSubmitWorkResult { is_valid : other . is_valid . into () , } } } impl From < super :: types :: EthSubmitWorkResult > for ffi :: EthSubmitWorkResult { fn from (other : super :: types :: EthSubmitWorkResult) -> Self { ffi :: EthSubmitWorkResult { is_valid : other . is_valid . into () , } } } impl From < ffi :: EthGetUncleCountByBlockHashResult > for super :: types :: EthGetUncleCountByBlockHashResult { fn from (other : ffi :: EthGetUncleCountByBlockHashResult) -> Self { super :: types :: EthGetUncleCountByBlockHashResult { number_uncles : other . number_uncles . into () , } } } impl From < super :: types :: EthGetUncleCountByBlockHashResult > for ffi :: EthGetUncleCountByBlockHashResult { fn from (other : super :: types :: EthGetUncleCountByBlockHashResult) -> Self { ffi :: EthGetUncleCountByBlockHashResult { number_uncles : other . number_uncles . into () , } } } impl From < ffi :: EthGetUncleCountByBlockNumberInput > for super :: types :: EthGetUncleCountByBlockNumberInput { fn from (other : ffi :: EthGetUncleCountByBlockNumberInput) -> Self { super :: types :: EthGetUncleCountByBlockNumberInput { block_number : other . block_number . into () , } } } impl From < super :: types :: EthGetUncleCountByBlockNumberInput > for ffi :: EthGetUncleCountByBlockNumberInput { fn from (other : super :: types :: EthGetUncleCountByBlockNumberInput) -> Self { ffi :: EthGetUncleCountByBlockNumberInput { block_number : other . block_number . into () , } } } impl From < ffi :: EthGetTransactionReceiptInput > for super :: types :: EthGetTransactionReceiptInput { fn from (other : ffi :: EthGetTransactionReceiptInput) -> Self { super :: types :: EthGetTransactionReceiptInput { transaction_hash : other . transaction_hash . into () , } } } impl From < super :: types :: EthGetTransactionReceiptInput > for ffi :: EthGetTransactionReceiptInput { fn from (other : super :: types :: EthGetTransactionReceiptInput) -> Self { ffi :: EthGetTransactionReceiptInput { transaction_hash : other . transaction_hash . into () , } } } impl From < ffi :: EthSendTransactionResult > for super :: types :: EthSendTransactionResult { fn from (other : ffi :: EthSendTransactionResult) -> Self { super :: types :: EthSendTransactionResult { hash : other . hash . into () , } } } impl From < super :: types :: EthSendTransactionResult > for ffi :: EthSendTransactionResult { fn from (other : super :: types :: EthSendTransactionResult) -> Self { ffi :: EthSendTransactionResult { hash : other . hash . into () , } } } impl From < ffi :: EthGetTransactionCountInput > for super :: types :: EthGetTransactionCountInput { fn from (other : ffi :: EthGetTransactionCountInput) -> Self { super :: types :: EthGetTransactionCountInput { address : other . address . into () , block_number : other . block_number . into () , } } } impl From < super :: types :: EthGetTransactionCountInput > for ffi :: EthGetTransactionCountInput { fn from (other : super :: types :: EthGetTransactionCountInput) -> Self { ffi :: EthGetTransactionCountInput { address : other . address . into () , block_number : other . block_number . into () , } } } impl From < ffi :: EthGetBlockTransactionCountByHashResult > for super :: types :: EthGetBlockTransactionCountByHashResult { fn from (other : ffi :: EthGetBlockTransactionCountByHashResult) -> Self { super :: types :: EthGetBlockTransactionCountByHashResult { number_transaction : other . number_transaction . into () , } } } impl From < super :: types :: EthGetBlockTransactionCountByHashResult > for ffi :: EthGetBlockTransactionCountByHashResult { fn from (other : super :: types :: EthGetBlockTransactionCountByHashResult) -> Self { ffi :: EthGetBlockTransactionCountByHashResult { number_transaction : other . number_transaction . into () , } } } impl From < ffi :: EthSignTransactionInput > for super :: types :: EthSignTransactionInput { fn from (other : ffi :: EthSignTransactionInput) -> Self { super :: types :: EthSignTransactionInput { transaction_info : Some (other . transaction_info . into ()) , } } } impl From < super :: types :: EthSignTransactionInput > for ffi :: EthSignTransactionInput { fn from (other : super :: types :: EthSignTransactionInput) -> Self { ffi :: EthSignTransactionInput { transaction_info : other . transaction_info . map (Into :: into) . unwrap_or_default () , } } } impl From < ffi :: EthBlockNumberResult > for super :: types :: EthBlockNumberResult { fn from (other : ffi :: EthBlockNumberResult) -> Self { super :: types :: EthBlockNumberResult { block_number : other . block_number . into () , } } } impl From < super :: types :: EthBlockNumberResult > for ffi :: EthBlockNumberResult { fn from (other : super :: types :: EthBlockNumberResult) -> Self { ffi :: EthBlockNumberResult { block_number : other . block_number . into () , } } } impl From < ffi :: EthGetStorageAtInput > for super :: types :: EthGetStorageAtInput { fn from (other : ffi :: EthGetStorageAtInput) -> Self { super :: types :: EthGetStorageAtInput { address : other . address . into () , position : other . position . into () , block_number : other . block_number . into () , } } } impl From < super :: types :: EthGetStorageAtInput > for ffi :: EthGetStorageAtInput { fn from (other : super :: types :: EthGetStorageAtInput) -> Self { ffi :: EthGetStorageAtInput { address : other . address . into () , position : other . position . into () , block_number : other . block_number . into () , } } } impl From < ffi :: EthGetBlockTransactionCountByNumberInput > for super :: types :: EthGetBlockTransactionCountByNumberInput { fn from (other : ffi :: EthGetBlockTransactionCountByNumberInput) -> Self { super :: types :: EthGetBlockTransactionCountByNumberInput { block_number : other . block_number . into () , } } } impl From < super :: types :: EthGetBlockTransactionCountByNumberInput > for ffi :: EthGetBlockTransactionCountByNumberInput { fn from (other : super :: types :: EthGetBlockTransactionCountByNumberInput) -> Self { ffi :: EthGetBlockTransactionCountByNumberInput { block_number : other . block_number . into () , } } } impl From < ffi :: NonUtxo > for super :: types :: NonUtxo { fn from (other : ffi :: NonUtxo) -> Self { super :: types :: NonUtxo { anchor_reward : other . anchor_reward . into () , burnt : other . burnt . into () , incentive_funding : other . incentive_funding . into () , loan : other . loan . into () , options : other . options . into () , unknown : other . unknown . into () , } } } impl From < super :: types :: NonUtxo > for ffi :: NonUtxo { fn from (other : super :: types :: NonUtxo) -> Self { ffi :: NonUtxo { anchor_reward : other . anchor_reward . into () , burnt : other . burnt . into () , incentive_funding : other . incentive_funding . into () , loan : other . loan . into () , options : other . options . into () , unknown : other . unknown . into () , } } } impl From < ffi :: EthGetTransactionByBlockHashAndIndexInput > for super :: types :: EthGetTransactionByBlockHashAndIndexInput { fn from (other : ffi :: EthGetTransactionByBlockHashAndIndexInput) -> Self { super :: types :: EthGetTransactionByBlockHashAndIndexInput { block_hash : other . block_hash . into () , index : other . index . into () , } } } impl From < super :: types :: EthGetTransactionByBlockHashAndIndexInput > for ffi :: EthGetTransactionByBlockHashAndIndexInput { fn from (other : super :: types :: EthGetTransactionByBlockHashAndIndexInput) -> Self { ffi :: EthGetTransactionByBlockHashAndIndexInput { block_hash : other . block_hash . into () , index : other . index . into () , } } } impl From < ffi :: EthGetBlockByHashInput > for super :: types :: EthGetBlockByHashInput { fn from (other : ffi :: EthGetBlockByHashInput) -> Self { super :: types :: EthGetBlockByHashInput { hash : other . hash . into () , full_transaction : other . full_transaction . into () , } } } impl From < super :: types :: EthGetBlockByHashInput > for ffi :: EthGetBlockByHashInput { fn from (other : super :: types :: EthGetBlockByHashInput) -> Self { ffi :: EthGetBlockByHashInput { hash : other . hash . into () , full_transaction : other . full_transaction . into () , } } } impl From < ffi :: BlockHashResult > for super :: types :: BlockHashResult { fn from (other : ffi :: BlockHashResult) -> Self { super :: types :: BlockHashResult { hash : other . hash . into () , } } } impl From < super :: types :: BlockHashResult > for ffi :: BlockHashResult { fn from (other : super :: types :: BlockHashResult) -> Self { ffi :: BlockHashResult { hash : other . hash . into () , } } } impl From < ffi :: Web3Sha3Input > for super :: types :: Web3Sha3Input { fn from (other : ffi :: Web3Sha3Input) -> Self { super :: types :: Web3Sha3Input { data : other . data . into () , } } } impl From < super :: types :: Web3Sha3Input > for ffi :: Web3Sha3Input { fn from (other : super :: types :: Web3Sha3Input) -> Self { ffi :: Web3Sha3Input { data : other . data . into () , } } } impl From < ffi :: EthTransactionInfo > for super :: types :: EthTransactionInfo { fn from (other : ffi :: EthTransactionInfo) -> Self { super :: types :: EthTransactionInfo { from : Some (other . from . into ()) , to : Some (other . to . into ()) , gas : Some (other . gas . into ()) , price : Some (other . price . into ()) , value : Some (other . value . into ()) , data : Some (other . data . into ()) , nonce : Some (other . nonce . into ()) , } } } impl From < super :: types :: EthTransactionInfo > for ffi :: EthTransactionInfo { fn from (other : super :: types :: EthTransactionInfo) -> Self { ffi :: EthTransactionInfo { from : other . from . map (Into :: into) . unwrap_or_default () , to : other . to . map (Into :: into) . unwrap_or_default () , gas : other . gas . map (Into :: into) . unwrap_or_default () , price : other . price . map (Into :: into) . unwrap_or_default () , value : other . value . map (Into :: into) . unwrap_or_default () , data : other . data . map (Into :: into) . unwrap_or_default () , nonce : other . nonce . map (Into :: into) . unwrap_or_default () , } } } impl From < ffi :: EthGetUncleCountByBlockNumberResult > for super :: types :: EthGetUncleCountByBlockNumberResult { fn from (other : ffi :: EthGetUncleCountByBlockNumberResult) -> Self { super :: types :: EthGetUncleCountByBlockNumberResult { number_uncles : other . number_uncles . into () , } } } impl From < super :: types :: EthGetUncleCountByBlockNumberResult > for ffi :: EthGetUncleCountByBlockNumberResult { fn from (other : super :: types :: EthGetUncleCountByBlockNumberResult) -> Self { ffi :: EthGetUncleCountByBlockNumberResult { number_uncles : other . number_uncles . into () , } } } impl From < ffi :: EthAccountsResult > for super :: types :: EthAccountsResult { fn from (other : ffi :: EthAccountsResult) -> Self { super :: types :: EthAccountsResult { accounts : other . accounts . into_iter () . map (Into :: into) . collect () , } } } impl From < super :: types :: EthAccountsResult > for ffi :: EthAccountsResult { fn from (other : super :: types :: EthAccountsResult) -> Self { ffi :: EthAccountsResult { accounts : other . accounts . into_iter () . map (Into :: into) . collect () , } } } impl From < ffi :: EthBlockInfo > for super :: types :: EthBlockInfo { fn from (other : ffi :: EthBlockInfo) -> Self { super :: types :: EthBlockInfo { block_number : other . block_number . into () , hash : other . hash . into () , parent_hash : other . parent_hash . into () , nonce : other . nonce . into () , sha3_uncles : other . sha3_uncles . into () , logs_bloom : other . logs_bloom . into () , transactions_root : other . transactions_root . into () , state_root : other . state_root . into () , receipt_root : other . receipt_root . into () , miner : other . miner . into () , difficulty : other . difficulty . into () , total_difficulty : other . total_difficulty . into () , extra_data : other . extra_data . into () , size : other . size . into () , gas_limit : other . gas_limit . into () , gas_used : other . gas_used . into () , timestamps : other . timestamps . into () , transactions : other . transactions . into_iter () . map (Into :: into) . collect () , uncles : other . uncles . into_iter () . map (Into :: into) . collect () , } } } impl From < super :: types :: EthBlockInfo > for ffi :: EthBlockInfo { fn from (other : super :: types :: EthBlockInfo) -> Self { ffi :: EthBlockInfo { block_number : other . block_number . into () , hash : other . hash . into () , parent_hash : other . parent_hash . into () , nonce : other . nonce . into () , sha3_uncles : other . sha3_uncles . into () , logs_bloom : other . logs_bloom . into () , transactions_root : other . transactions_root . into () , state_root : other . state_root . into () , receipt_root : other . receipt_root . into () , miner : other . miner . into () , difficulty : other . difficulty . into () , total_difficulty : other . total_difficulty . into () , extra_data : other . extra_data . into () , size : other . size . into () , gas_limit : other . gas_limit . into () , gas_used : other . gas_used . into () , timestamps : other . timestamps . into () , transactions : other . transactions . into_iter () . map (Into :: into) . collect () , uncles : other . uncles . into_iter () . map (Into :: into) . collect () , } } } impl From < ffi :: EthCompileSolidityResult > for super :: types :: EthCompileSolidityResult { fn from (other : ffi :: EthCompileSolidityResult) -> Self { super :: types :: EthCompileSolidityResult { compiled_code : other . compiled_code . into () , } } } impl From < super :: types :: EthCompileSolidityResult > for ffi :: EthCompileSolidityResult { fn from (other : super :: types :: EthCompileSolidityResult) -> Self { ffi :: EthCompileSolidityResult { compiled_code : other . compiled_code . into () , } } } impl From < ffi :: NetPeerCountResult > for super :: types :: NetPeerCountResult { fn from (other : ffi :: NetPeerCountResult) -> Self { super :: types :: NetPeerCountResult { number_peer : other . number_peer . into () , } } } impl From < super :: types :: NetPeerCountResult > for ffi :: NetPeerCountResult { fn from (other : super :: types :: NetPeerCountResult) -> Self { ffi :: NetPeerCountResult { number_peer : other . number_peer . into () , } } } impl From < ffi :: EthGetTransactionReceiptResult > for super :: types :: EthGetTransactionReceiptResult { fn from (other : ffi :: EthGetTransactionReceiptResult) -> Self { super :: types :: EthGetTransactionReceiptResult { transaction_receipt : Some (other . transaction_receipt . into ()) , } } } impl From < super :: types :: EthGetTransactionReceiptResult > for ffi :: EthGetTransactionReceiptResult { fn from (other : super :: types :: EthGetTransactionReceiptResult) -> Self { ffi :: EthGetTransactionReceiptResult { transaction_receipt : other . transaction_receipt . map (Into :: into) . unwrap_or_default () , } } } impl From < ffi :: EthSubmitHashrateInput > for super :: types :: EthSubmitHashrateInput { fn from (other : ffi :: EthSubmitHashrateInput) -> Self { super :: types :: EthSubmitHashrateInput { hash_rate : other . hash_rate . into () , id : other . id . into () , } } } impl From < super :: types :: EthSubmitHashrateInput > for ffi :: EthSubmitHashrateInput { fn from (other : super :: types :: EthSubmitHashrateInput) -> Self { ffi :: EthSubmitHashrateInput { hash_rate : other . hash_rate . into () , id : other . id . into () , } } } impl From < ffi :: EthSignTransactionResult > for super :: types :: EthSignTransactionResult { fn from (other : ffi :: EthSignTransactionResult) -> Self { super :: types :: EthSignTransactionResult { transaction : other . transaction . into () , } } } impl From < super :: types :: EthSignTransactionResult > for ffi :: EthSignTransactionResult { fn from (other : super :: types :: EthSignTransactionResult) -> Self { ffi :: EthSignTransactionResult { transaction : other . transaction . into () , } } } impl From < ffi :: EthMiningResult > for super :: types :: EthMiningResult { fn from (other : ffi :: EthMiningResult) -> Self { super :: types :: EthMiningResult { is_mining : other . is_mining . into () , } } } impl From < super :: types :: EthMiningResult > for ffi :: EthMiningResult { fn from (other : super :: types :: EthMiningResult) -> Self { ffi :: EthMiningResult { is_mining : other . is_mining . into () , } } } impl From < ffi :: EthGetUncleCountByBlockHashInput > for super :: types :: EthGetUncleCountByBlockHashInput { fn from (other : ffi :: EthGetUncleCountByBlockHashInput) -> Self { super :: types :: EthGetUncleCountByBlockHashInput { block_hash : other . block_hash . into () , } } } impl From < super :: types :: EthGetUncleCountByBlockHashInput > for ffi :: EthGetUncleCountByBlockHashInput { fn from (other : super :: types :: EthGetUncleCountByBlockHashInput) -> Self { ffi :: EthGetUncleCountByBlockHashInput { block_hash : other . block_hash . into () , } } } impl From < ffi :: EthGetCodeResult > for super :: types :: EthGetCodeResult { fn from (other : ffi :: EthGetCodeResult) -> Self { super :: types :: EthGetCodeResult { code : other . code . into () , } } } impl From < super :: types :: EthGetCodeResult > for ffi :: EthGetCodeResult { fn from (other : super :: types :: EthGetCodeResult) -> Self { ffi :: EthGetCodeResult { code : other . code . into () , } } } impl From < ffi :: EthSendRawTransactionInput > for super :: types :: EthSendRawTransactionInput { fn from (other : ffi :: EthSendRawTransactionInput) -> Self { super :: types :: EthSendRawTransactionInput { transaction : other . transaction . into () , } } } impl From < super :: types :: EthSendRawTransactionInput > for ffi :: EthSendRawTransactionInput { fn from (other : super :: types :: EthSendRawTransactionInput) -> Self { ffi :: EthSendRawTransactionInput { transaction : other . transaction . into () , } } } impl From < ffi :: EthCompileSolidityInput > for super :: types :: EthCompileSolidityInput { fn from (other : ffi :: EthCompileSolidityInput) -> Self { super :: types :: EthCompileSolidityInput { code : other . code . into () , } } } impl From < super :: types :: EthCompileSolidityInput > for ffi :: EthCompileSolidityInput { fn from (other : super :: types :: EthCompileSolidityInput) -> Self { ffi :: EthCompileSolidityInput { code : other . code . into () , } } } impl From < ffi :: EthSubmitHashrateResult > for super :: types :: EthSubmitHashrateResult { fn from (other : ffi :: EthSubmitHashrateResult) -> Self { super :: types :: EthSubmitHashrateResult { is_valid : other . is_valid . into () , } } } impl From < super :: types :: EthSubmitHashrateResult > for ffi :: EthSubmitHashrateResult { fn from (other : super :: types :: EthSubmitHashrateResult) -> Self { ffi :: EthSubmitHashrateResult { is_valid : other . is_valid . into () , } } } impl From < ffi :: ScriptSig > for super :: types :: ScriptSig { fn from (other : ffi :: ScriptSig) -> Self { super :: types :: ScriptSig { field_asm : other . field_asm . into () , hex : other . hex . into () , } } } impl From < super :: types :: ScriptSig > for ffi :: ScriptSig { fn from (other : super :: types :: ScriptSig) -> Self { ffi :: ScriptSig { field_asm : other . field_asm . into () , hex : other . hex . into () , } } } impl From < ffi :: EthGetBalanceInput > for super :: types :: EthGetBalanceInput { fn from (other : ffi :: EthGetBalanceInput) -> Self { super :: types :: EthGetBalanceInput { address : other . address . into () , block_number : other . block_number . into () , } } } impl From < super :: types :: EthGetBalanceInput > for ffi :: EthGetBalanceInput { fn from (other : super :: types :: EthGetBalanceInput) -> Self { ffi :: EthGetBalanceInput { address : other . address . into () , block_number : other . block_number . into () , } } } impl From < ffi :: EthSignResult > for super :: types :: EthSignResult { fn from (other : ffi :: EthSignResult) -> Self { super :: types :: EthSignResult { signature : other . signature . into () , } } } impl From < super :: types :: EthSignResult > for ffi :: EthSignResult { fn from (other : super :: types :: EthSignResult) -> Self { ffi :: EthSignResult { signature : other . signature . into () , } } } impl From < ffi :: EthGetBalanceResult > for super :: types :: EthGetBalanceResult { fn from (other : ffi :: EthGetBalanceResult) -> Self { super :: types :: EthGetBalanceResult { balance : other . balance . into () , } } } impl From < super :: types :: EthGetBalanceResult > for ffi :: EthGetBalanceResult { fn from (other : super :: types :: EthGetBalanceResult) -> Self { ffi :: EthGetBalanceResult { balance : other . balance . into () , } } } impl From < ffi :: EthCoinBaseResult > for super :: types :: EthCoinBaseResult { fn from (other : ffi :: EthCoinBaseResult) -> Self { super :: types :: EthCoinBaseResult { address : other . address . into () , } } } impl From < super :: types :: EthCoinBaseResult > for ffi :: EthCoinBaseResult { fn from (other : super :: types :: EthCoinBaseResult) -> Self { ffi :: EthCoinBaseResult { address : other . address . into () , } } } impl From < ffi :: EthHashRateResult > for super :: types :: EthHashRateResult { fn from (other : ffi :: EthHashRateResult) -> Self { super :: types :: EthHashRateResult { hash_rate : other . hash_rate . into () , } } } impl From < super :: types :: EthHashRateResult > for ffi :: EthHashRateResult { fn from (other : super :: types :: EthHashRateResult) -> Self { ffi :: EthHashRateResult { hash_rate : other . hash_rate . into () , } } } impl From < ffi :: EthGetBlockByNumberResult > for super :: types :: EthGetBlockByNumberResult { fn from (other : ffi :: EthGetBlockByNumberResult) -> Self { super :: types :: EthGetBlockByNumberResult { block_info : Some (other . block_info . into ()) , } } } impl From < super :: types :: EthGetBlockByNumberResult > for ffi :: EthGetBlockByNumberResult { fn from (other : super :: types :: EthGetBlockByNumberResult) -> Self { ffi :: EthGetBlockByNumberResult { block_info : other . block_info . map (Into :: into) . unwrap_or_default () , } } } impl From < ffi :: EthGetTransactionByBlockNumberAndIndexInput > for super :: types :: EthGetTransactionByBlockNumberAndIndexInput { fn from (other : ffi :: EthGetTransactionByBlockNumberAndIndexInput) -> Self { super :: types :: EthGetTransactionByBlockNumberAndIndexInput { block_number : other . block_number . into () , index : other . index . into () , } } } impl From < super :: types :: EthGetTransactionByBlockNumberAndIndexInput > for ffi :: EthGetTransactionByBlockNumberAndIndexInput { fn from (other : super :: types :: EthGetTransactionByBlockNumberAndIndexInput) -> Self { ffi :: EthGetTransactionByBlockNumberAndIndexInput { block_number : other . block_number . into () , index : other . index . into () , } } } impl From < ffi :: Web3Sha3Result > for super :: types :: Web3Sha3Result { fn from (other : ffi :: Web3Sha3Result) -> Self { super :: types :: Web3Sha3Result { data : other . data . into () , } } } impl From < super :: types :: Web3Sha3Result > for ffi :: Web3Sha3Result { fn from (other : super :: types :: Web3Sha3Result) -> Self { ffi :: Web3Sha3Result { data : other . data . into () , } } } impl From < ffi :: NetVersionResult > for super :: types :: NetVersionResult { fn from (other : ffi :: NetVersionResult) -> Self { super :: types :: NetVersionResult { network_version : other . network_version . into () , } } } impl From < super :: types :: NetVersionResult > for ffi :: NetVersionResult { fn from (other : super :: types :: NetVersionResult) -> Self { ffi :: NetVersionResult { network_version : other . network_version . into () , } } } impl From < ffi :: EthGetUncleByBlockHashAndIndexResult > for super :: types :: EthGetUncleByBlockHashAndIndexResult { fn from (other : ffi :: EthGetUncleByBlockHashAndIndexResult) -> Self { super :: types :: EthGetUncleByBlockHashAndIndexResult { block_info : Some (other . block_info . into ()) , } } } impl From < super :: types :: EthGetUncleByBlockHashAndIndexResult > for ffi :: EthGetUncleByBlockHashAndIndexResult { fn from (other : super :: types :: EthGetUncleByBlockHashAndIndexResult) -> Self { ffi :: EthGetUncleByBlockHashAndIndexResult { block_info : other . block_info . map (Into :: into) . unwrap_or_default () , } } } impl From < ffi :: EthGetTransactionCountResult > for super :: types :: EthGetTransactionCountResult { fn from (other : ffi :: EthGetTransactionCountResult) -> Self { super :: types :: EthGetTransactionCountResult { number_transaction : other . number_transaction . into () , } } } impl From < super :: types :: EthGetTransactionCountResult > for ffi :: EthGetTransactionCountResult { fn from (other : super :: types :: EthGetTransactionCountResult) -> Self { ffi :: EthGetTransactionCountResult { number_transaction : other . number_transaction . into () , } } } impl From < ffi :: EthTransactionReceipt > for super :: types :: EthTransactionReceipt { fn from (other : ffi :: EthTransactionReceipt) -> Self { super :: types :: EthTransactionReceipt { transaction_hash : other . transaction_hash . into () , transaction_index : other . transaction_index . into () , block_hash : other . block_hash . into () , block_number : other . block_number . into () , from : other . from . into () , to : other . to . into () , cumulative_gas_used : other . cumulative_gas_used . into () , effective_gas_price : other . effective_gas_price . into () , gas_used : other . gas_used . into () , contract_address : other . contract_address . into () , logs : other . logs . into_iter () . map (Into :: into) . collect () , logs_bloom : other . logs_bloom . into () , field_type : other . field_type . into () , root : Some (other . root . into ()) , status : Some (other . status . into ()) , } } } impl From < super :: types :: EthTransactionReceipt > for ffi :: EthTransactionReceipt { fn from (other : super :: types :: EthTransactionReceipt) -> Self { ffi :: EthTransactionReceipt { transaction_hash : other . transaction_hash . into () , transaction_index : other . transaction_index . into () , block_hash : other . block_hash . into () , block_number : other . block_number . into () , from : other . from . into () , to : other . to . into () , cumulative_gas_used : other . cumulative_gas_used . into () , effective_gas_price : other . effective_gas_price . into () , gas_used : other . gas_used . into () , contract_address : other . contract_address . into () , logs : other . logs . into_iter () . map (Into :: into) . collect () , logs_bloom : other . logs_bloom . into () , field_type : other . field_type . into () , root : other . root . map (Into :: into) . unwrap_or_default () , status : other . status . map (Into :: into) . unwrap_or_default () , } } } impl From < ffi :: EthEstimateGasResult > for super :: types :: EthEstimateGasResult { fn from (other : ffi :: EthEstimateGasResult) -> Self { super :: types :: EthEstimateGasResult { gas_used : other . gas_used . into () , } } } impl From < super :: types :: EthEstimateGasResult > for ffi :: EthEstimateGasResult { fn from (other : super :: types :: EthEstimateGasResult) -> Self { ffi :: EthEstimateGasResult { gas_used : other . gas_used . into () , } } } impl From < ffi :: BlockInput > for super :: types :: BlockInput { fn from (other : ffi :: BlockInput) -> Self { super :: types :: BlockInput { blockhash : other . blockhash . into () , verbosity : other . verbosity . into () , } } } impl From < super :: types :: BlockInput > for ffi :: BlockInput { fn from (other : super :: types :: BlockInput) -> Self { ffi :: BlockInput { blockhash : other . blockhash . into () , verbosity : other . verbosity . into () , } } } impl From < ffi :: EthGetBlockTransactionCountByHashInput > for super :: types :: EthGetBlockTransactionCountByHashInput { fn from (other : ffi :: EthGetBlockTransactionCountByHashInput) -> Self { super :: types :: EthGetBlockTransactionCountByHashInput { block_hash : other . block_hash . into () , } } } impl From < super :: types :: EthGetBlockTransactionCountByHashInput > for ffi :: EthGetBlockTransactionCountByHashInput { fn from (other : super :: types :: EthGetBlockTransactionCountByHashInput) -> Self { ffi :: EthGetBlockTransactionCountByHashInput { block_hash : other . block_hash . into () , } } } impl From < ffi :: EthSyncingResult > for super :: types :: EthSyncingResult { fn from (other : ffi :: EthSyncingResult) -> Self { super :: types :: EthSyncingResult { status : Some (other . status . into ()) , sync_info : Some (other . sync_info . into ()) , } } } impl From < super :: types :: EthSyncingResult > for ffi :: EthSyncingResult { fn from (other : super :: types :: EthSyncingResult) -> Self { ffi :: EthSyncingResult { status : other . status . map (Into :: into) . unwrap_or_default () , sync_info : other . sync_info . map (Into :: into) . unwrap_or_default () , } } } impl From < ffi :: EthGetTransactionByHashResult > for super :: types :: EthGetTransactionByHashResult { fn from (other : ffi :: EthGetTransactionByHashResult) -> Self { super :: types :: EthGetTransactionByHashResult { transaction : Some (other . transaction . into ()) , } } } impl From < super :: types :: EthGetTransactionByHashResult > for ffi :: EthGetTransactionByHashResult { fn from (other : super :: types :: EthGetTransactionByHashResult) -> Self { ffi :: EthGetTransactionByHashResult { transaction : other . transaction . map (Into :: into) . unwrap_or_default () , } } } impl From < ffi :: EthGasPriceResult > for super :: types :: EthGasPriceResult { fn from (other : ffi :: EthGasPriceResult) -> Self { super :: types :: EthGasPriceResult { gas_price : other . gas_price . into () , } } } impl From < super :: types :: EthGasPriceResult > for ffi :: EthGasPriceResult { fn from (other : super :: types :: EthGasPriceResult) -> Self { ffi :: EthGasPriceResult { gas_price : other . gas_price . into () , } } } impl From < ffi :: EthGetBlockByHashResult > for super :: types :: EthGetBlockByHashResult { fn from (other : ffi :: EthGetBlockByHashResult) -> Self { super :: types :: EthGetBlockByHashResult { block_info : Some (other . block_info . into ()) , } } } impl From < super :: types :: EthGetBlockByHashResult > for ffi :: EthGetBlockByHashResult { fn from (other : super :: types :: EthGetBlockByHashResult) -> Self { ffi :: EthGetBlockByHashResult { block_info : other . block_info . map (Into :: into) . unwrap_or_default () , } } } impl From < ffi :: EthSubmitWorkInput > for super :: types :: EthSubmitWorkInput { fn from (other : ffi :: EthSubmitWorkInput) -> Self { super :: types :: EthSubmitWorkInput { nounce : other . nounce . into () , pow_hash : other . pow_hash . into () , mix_digest : other . mix_digest . into () , } } } impl From < super :: types :: EthSubmitWorkInput > for ffi :: EthSubmitWorkInput { fn from (other : super :: types :: EthSubmitWorkInput) -> Self { ffi :: EthSubmitWorkInput { nounce : other . nounce . into () , pow_hash : other . pow_hash . into () , mix_digest : other . mix_digest . into () , } } } impl From < ffi :: EthGetWorkResult > for super :: types :: EthGetWorkResult { fn from (other : ffi :: EthGetWorkResult) -> Self { super :: types :: EthGetWorkResult { currentblock : other . currentblock . into () , seed_hash : other . seed_hash . into () , target : other . target . into () , } } } impl From < super :: types :: EthGetWorkResult > for ffi :: EthGetWorkResult { fn from (other : super :: types :: EthGetWorkResult) -> Self { ffi :: EthGetWorkResult { currentblock : other . currentblock . into () , seed_hash : other . seed_hash . into () , target : other . target . into () , } } } impl From < ffi :: EthGetTransactionByBlockNumberAndIndexResult > for super :: types :: EthGetTransactionByBlockNumberAndIndexResult { fn from (other : ffi :: EthGetTransactionByBlockNumberAndIndexResult) -> Self { super :: types :: EthGetTransactionByBlockNumberAndIndexResult { transaction : Some (other . transaction . into ()) , } } } impl From < super :: types :: EthGetTransactionByBlockNumberAndIndexResult > for ffi :: EthGetTransactionByBlockNumberAndIndexResult { fn from (other : super :: types :: EthGetTransactionByBlockNumberAndIndexResult) -> Self { ffi :: EthGetTransactionByBlockNumberAndIndexResult { transaction : other . transaction . map (Into :: into) . unwrap_or_default () , } } } impl From < ffi :: EthGetTransactionByHashInput > for super :: types :: EthGetTransactionByHashInput { fn from (other : ffi :: EthGetTransactionByHashInput) -> Self { super :: types :: EthGetTransactionByHashInput { hash : other . hash . into () , } } } impl From < super :: types :: EthGetTransactionByHashInput > for ffi :: EthGetTransactionByHashInput { fn from (other : super :: types :: EthGetTransactionByHashInput) -> Self { ffi :: EthGetTransactionByHashInput { hash : other . hash . into () , } } } impl From < ffi :: EthProtocolVersionResult > for super :: types :: EthProtocolVersionResult { fn from (other : ffi :: EthProtocolVersionResult) -> Self { super :: types :: EthProtocolVersionResult { protocol_version : other . protocol_version . into () , } } } impl From < super :: types :: EthProtocolVersionResult > for ffi :: EthProtocolVersionResult { fn from (other : super :: types :: EthProtocolVersionResult) -> Self { ffi :: EthProtocolVersionResult { protocol_version : other . protocol_version . into () , } } } impl From < ffi :: EthSyncingInfo > for super :: types :: EthSyncingInfo { fn from (other : ffi :: EthSyncingInfo) -> Self { super :: types :: EthSyncingInfo { starting_block : other . starting_block . into () , current_block : other . current_block . into () , highest_block : other . highest_block . into () , } } } impl From < super :: types :: EthSyncingInfo > for ffi :: EthSyncingInfo { fn from (other : super :: types :: EthSyncingInfo) -> Self { ffi :: EthSyncingInfo { starting_block : other . starting_block . into () , current_block : other . current_block . into () , highest_block : other . highest_block . into () , } } } impl From < ffi :: EthCompileLllResult > for super :: types :: EthCompileLllResult { fn from (other : ffi :: EthCompileLllResult) -> Self { super :: types :: EthCompileLllResult { compiled_code : other . compiled_code . into () , } } } impl From < super :: types :: EthCompileLllResult > for ffi :: EthCompileLllResult { fn from (other : super :: types :: EthCompileLllResult) -> Self { ffi :: EthCompileLllResult { compiled_code : other . compiled_code . into () , } } } impl From < ffi :: EthCompileLllInput > for super :: types :: EthCompileLllInput { fn from (other : ffi :: EthCompileLllInput) -> Self { super :: types :: EthCompileLllInput { code : other . code . into () , } } } impl From < super :: types :: EthCompileLllInput > for ffi :: EthCompileLllInput { fn from (other : super :: types :: EthCompileLllInput) -> Self { ffi :: EthCompileLllInput { code : other . code . into () , } } } impl From < ffi :: Block > for super :: types :: Block { fn from (other : ffi :: Block) -> Self { super :: types :: Block { hash : other . hash . into () , confirmations : other . confirmations . into () , size : other . size . into () , strippedsize : other . strippedsize . into () , weight : other . weight . into () , height : other . height . into () , version : other . version . into () , version_hex : other . version_hex . into () , merkleroot : other . merkleroot . into () , tx : other . tx . into_iter () . map (Into :: into) . collect () , time : other . time . into () , mediantime : other . mediantime . into () , nonce : other . nonce . into () , bits : other . bits . into () , difficulty : other . difficulty . into () , chainwork : other . chainwork . into () , n_tx : other . n_tx . into () , previous_block_hash : other . previous_block_hash . into () , next_block_hash : other . next_block_hash . into () , masternode : other . masternode . into () , minter : other . minter . into () , minted_blocks : other . minted_blocks . into () , stake_modifier : other . stake_modifier . into () , nonutxo : other . nonutxo . into_iter () . map (Into :: into) . collect () , } } } impl From < super :: types :: Block > for ffi :: Block { fn from (other : super :: types :: Block) -> Self { ffi :: Block { hash : other . hash . into () , confirmations : other . confirmations . into () , size : other . size . into () , strippedsize : other . strippedsize . into () , weight : other . weight . into () , height : other . height . into () , version : other . version . into () , version_hex : other . version_hex . into () , merkleroot : other . merkleroot . into () , tx : other . tx . into_iter () . map (Into :: into) . collect () , time : other . time . into () , mediantime : other . mediantime . into () , nonce : other . nonce . into () , bits : other . bits . into () , difficulty : other . difficulty . into () , chainwork : other . chainwork . into () , n_tx : other . n_tx . into () , previous_block_hash : other . previous_block_hash . into () , next_block_hash : other . next_block_hash . into () , masternode : other . masternode . into () , minter : other . minter . into () , minted_blocks : other . minted_blocks . into () , stake_modifier : other . stake_modifier . into () , nonutxo : other . nonutxo . into_iter () . map (Into :: into) . collect () , } } } impl From < ffi :: EthGetBlockByNumberInput > for super :: types :: EthGetBlockByNumberInput { fn from (other : ffi :: EthGetBlockByNumberInput) -> Self { super :: types :: EthGetBlockByNumberInput { number : other . number . into () , full_transaction : other . full_transaction . into () , } } } impl From < super :: types :: EthGetBlockByNumberInput > for ffi :: EthGetBlockByNumberInput { fn from (other : super :: types :: EthGetBlockByNumberInput) -> Self { ffi :: EthGetBlockByNumberInput { number : other . number . into () , full_transaction : other . full_transaction . into () , } } } # [allow (non_snake_case)] # [allow (clippy :: borrowed_box)] fn CallEth_Accounts (client : & Box < Client >) -> Result < ffi :: EthAccountsResult , Box < dyn std :: error :: Error >> { let (tx , mut rx) = tokio :: sync :: mpsc :: channel (1) ; let c = client . inner . clone () ; client . handle . spawn (async move { let params = jsonrpsee_core :: rpc_params ! [] ; let resp : Result < super :: types :: EthAccountsResult , _ > = c . request ("eth_accounts" , params) . await ; let _ = tx . send (resp) . await ; }) ; Ok (rx . blocking_recv () . unwrap () . map (Into :: into) ?) } # [allow (non_snake_case)] # [allow (clippy :: borrowed_box)] fn CallEth_Call (client : & Box < Client > , eth_call_input : EthCallInput) -> Result < ffi :: EthCallResult , Box < dyn std :: error :: Error >> { let (tx , mut rx) = tokio :: sync :: mpsc :: channel (1) ; let c = client . inner . clone () ; client . handle . spawn (async move { let eth_call_input = super :: types :: EthCallInput :: from (eth_call_input) ; let params = jsonrpsee_core :: rpc_params ! [& eth_call_input . transaction_info , & eth_call_input . block_number] ; let resp : Result < super :: types :: EthCallResult , _ > = c . request ("eth_call" , params) . await ; let _ = tx . send (resp) . await ; }) ; Ok (rx . blocking_recv () . unwrap () . map (Into :: into) ?) } # [allow (non_snake_case)] # [allow (clippy :: borrowed_box)] fn CallEth_GetBalance (client : & Box < Client > , eth_get_balance_input : EthGetBalanceInput) -> Result < ffi :: EthGetBalanceResult , Box < dyn std :: error :: Error >> { let (tx , mut rx) = tokio :: sync :: mpsc :: channel (1) ; let c = client . inner . clone () ; client . handle . spawn (async move { let eth_get_balance_input = super :: types :: EthGetBalanceInput :: from (eth_get_balance_input) ; let params = jsonrpsee_core :: rpc_params ! [& eth_get_balance_input . address , & eth_get_balance_input . block_number] ; let resp : Result < super :: types :: EthGetBalanceResult , _ > = c . request ("eth_getbalance" , params) . await ; let _ = tx . send (resp) . await ; }) ; Ok (rx . blocking_recv () . unwrap () . map (Into :: into) ?) } # [allow (non_snake_case)] # [allow (clippy :: borrowed_box)] fn CallEth_GetBlockByHash (client : & Box < Client > , eth_get_block_by_hash_input : EthGetBlockByHashInput) -> Result < ffi :: EthBlockInfo , Box < dyn std :: error :: Error >> { let (tx , mut rx) = tokio :: sync :: mpsc :: channel (1) ; let c = client . inner . clone () ; client . handle . spawn (async move { let eth_get_block_by_hash_input = super :: types :: EthGetBlockByHashInput :: from (eth_get_block_by_hash_input) ; let params = jsonrpsee_core :: rpc_params ! [& eth_get_block_by_hash_input . hash , & eth_get_block_by_hash_input . full_transaction] ; let resp : Result < super :: types :: EthBlockInfo , _ > = c . request ("eth_getblockbyhash" , params) . await ; let _ = tx . send (resp) . await ; }) ; Ok (rx . blocking_recv () . unwrap () . map (Into :: into) ?) } # [allow (non_snake_case)] # [allow (clippy :: borrowed_box)] fn CallEth_ChainId (client : & Box < Client >) -> Result < ffi :: EthChainIdResult , Box < dyn std :: error :: Error >> { let (tx , mut rx) = tokio :: sync :: mpsc :: channel (1) ; let c = client . inner . clone () ; client . handle . spawn (async move { let params = jsonrpsee_core :: rpc_params ! [] ; let resp : Result < super :: types :: EthChainIdResult , _ > = c . request ("eth_chainid" , params) . await ; let _ = tx . send (resp) . await ; }) ; Ok (rx . blocking_recv () . unwrap () . map (Into :: into) ?) } # [allow (non_snake_case)] # [allow (clippy :: borrowed_box)] fn CallNet_Version (client : & Box < Client >) -> Result < ffi :: EthChainIdResult , Box < dyn std :: error :: Error >> { let (tx , mut rx) = tokio :: sync :: mpsc :: channel (1) ; let c = client . inner . clone () ; client . handle . spawn (async move { let params = jsonrpsee_core :: rpc_params ! [] ; let resp : Result < super :: types :: EthChainIdResult , _ > = c . request ("net_version" , params) . await ; let _ = tx . send (resp) . await ; }) ; Ok (rx . blocking_recv () . unwrap () . map (Into :: into) ?) } # [allow (non_snake_case)] # [allow (clippy :: borrowed_box)] fn CallEth_BlockNumber (client : & Box < Client >) -> Result < ffi :: EthBlockNumberResult , Box < dyn std :: error :: Error >> { let (tx , mut rx) = tokio :: sync :: mpsc :: channel (1) ; let c = client . inner . clone () ; client . handle . spawn (async move { let params = jsonrpsee_core :: rpc_params ! [] ; let resp : Result < super :: types :: EthBlockNumberResult , _ > = c . request ("eth_blocknumber" , params) . await ; let _ = tx . send (resp) . await ; }) ; Ok (rx . blocking_recv () . unwrap () . map (Into :: into) ?) } # [allow (non_snake_case)] # [allow (clippy :: borrowed_box)] fn CallEth_GetBlockByNumber (client : & Box < Client > , eth_get_block_by_number_input : EthGetBlockByNumberInput) -> Result < ffi :: EthBlockInfo , Box < dyn std :: error :: Error >> { let (tx , mut rx) = tokio :: sync :: mpsc :: channel (1) ; let c = client . inner . clone () ; client . handle . spawn (async move { let eth_get_block_by_number_input = super :: types :: EthGetBlockByNumberInput :: from (eth_get_block_by_number_input) ; let params = jsonrpsee_core :: rpc_params ! [& eth_get_block_by_number_input . number , & eth_get_block_by_number_input . full_transaction] ; let resp : Result < super :: types :: EthBlockInfo , _ > = c . request ("eth_getblockbynumber" , params) . await ; let _ = tx . send (resp) . await ; }) ; Ok (rx . blocking_recv () . unwrap () . map (Into :: into) ?) } # [allow (non_snake_case)] # [allow (clippy :: borrowed_box)] fn CallEth_GetTransactionByHash (client : & Box < Client > , eth_get_transaction_by_hash_input : EthGetTransactionByHashInput) -> Result < ffi :: EthTransactionInfo , Box < dyn std :: error :: Error >> { let (tx , mut rx) = tokio :: sync :: mpsc :: channel (1) ; let c = client . inner . clone () ; client . handle . spawn (async move { let eth_get_transaction_by_hash_input = super :: types :: EthGetTransactionByHashInput :: from (eth_get_transaction_by_hash_input) ; let params = jsonrpsee_core :: rpc_params ! [& eth_get_transaction_by_hash_input . hash] ; let resp : Result < super :: types :: EthTransactionInfo , _ > = c . request ("eth_gettransactionbyhash" , params) . await ; let _ = tx . send (resp) . await ; }) ; Ok (rx . blocking_recv () . unwrap () . map (Into :: into) ?) } # [allow (non_snake_case)] # [allow (clippy :: borrowed_box)] fn CallEth_GetTransactionByBlockHashAndIndex (client : & Box < Client > , eth_get_transaction_by_block_hash_and_index_input : EthGetTransactionByBlockHashAndIndexInput) -> Result < ffi :: EthTransactionInfo , Box < dyn std :: error :: Error >> { let (tx , mut rx) = tokio :: sync :: mpsc :: channel (1) ; let c = client . inner . clone () ; client . handle . spawn (async move { let eth_get_transaction_by_block_hash_and_index_input = super :: types :: EthGetTransactionByBlockHashAndIndexInput :: from (eth_get_transaction_by_block_hash_and_index_input) ; let params = jsonrpsee_core :: rpc_params ! [& eth_get_transaction_by_block_hash_and_index_input . block_hash , & eth_get_transaction_by_block_hash_and_index_input . index] ; let resp : Result < super :: types :: EthTransactionInfo , _ > = c . request ("eth_gettransactionbyblockhashandindex" , params) . await ; let _ = tx . send (resp) . await ; }) ; Ok (rx . blocking_recv () . unwrap () . map (Into :: into) ?) } # [allow (non_snake_case)] # [allow (clippy :: borrowed_box)] fn CallEth_GetTransactionByBlockNumberAndIndex (client : & Box < Client > , eth_get_transaction_by_block_number_and_index_input : EthGetTransactionByBlockNumberAndIndexInput) -> Result < ffi :: EthTransactionInfo , Box < dyn std :: error :: Error >> { let (tx , mut rx) = tokio :: sync :: mpsc :: channel (1) ; let c = client . inner . clone () ; client . handle . spawn (async move { let eth_get_transaction_by_block_number_and_index_input = super :: types :: EthGetTransactionByBlockNumberAndIndexInput :: from (eth_get_transaction_by_block_number_and_index_input) ; let params = jsonrpsee_core :: rpc_params ! [& eth_get_transaction_by_block_number_and_index_input . block_number , & eth_get_transaction_by_block_number_and_index_input . index] ; let resp : Result < super :: types :: EthTransactionInfo , _ > = c . request ("eth_gettransactionbyblocknumberandindex" , params) . await ; let _ = tx . send (resp) . await ; }) ; Ok (rx . blocking_recv () . unwrap () . map (Into :: into) ?) } # [allow (non_snake_case)] # [allow (clippy :: borrowed_box)] fn CallEth_Mining (client : & Box < Client >) -> Result < ffi :: EthMiningResult , Box < dyn std :: error :: Error >> { let (tx , mut rx) = tokio :: sync :: mpsc :: channel (1) ; let c = client . inner . clone () ; client . handle . spawn (async move { let params = jsonrpsee_core :: rpc_params ! [] ; let resp : Result < super :: types :: EthMiningResult , _ > = c . request ("eth_mining" , params) . await ; let _ = tx . send (resp) . await ; }) ; Ok (rx . blocking_recv () . unwrap () . map (Into :: into) ?) } # [allow (non_snake_case)] # [allow (clippy :: borrowed_box)] fn CallEth_GetBlockTransactionCountByHash (client : & Box < Client > , eth_get_block_transaction_count_by_hash_input : EthGetBlockTransactionCountByHashInput) -> Result < ffi :: EthGetBlockTransactionCountByHashResult , Box < dyn std :: error :: Error >> { let (tx , mut rx) = tokio :: sync :: mpsc :: channel (1) ; let c = client . inner . clone () ; client . handle . spawn (async move { let eth_get_block_transaction_count_by_hash_input = super :: types :: EthGetBlockTransactionCountByHashInput :: from (eth_get_block_transaction_count_by_hash_input) ; let params = jsonrpsee_core :: rpc_params ! [& eth_get_block_transaction_count_by_hash_input . block_hash] ; let resp : Result < super :: types :: EthGetBlockTransactionCountByHashResult , _ > = c . request ("eth_getblocktransactioncountbyhash" , params) . await ; let _ = tx . send (resp) . await ; }) ; Ok (rx . blocking_recv () . unwrap () . map (Into :: into) ?) } # [allow (non_snake_case)] # [allow (clippy :: borrowed_box)] fn CallEth_GetBlockTransactionCountByNumber (client : & Box < Client > , eth_get_block_transaction_count_by_number_input : EthGetBlockTransactionCountByNumberInput) -> Result < ffi :: EthGetBlockTransactionCountByNumberResult , Box < dyn std :: error :: Error >> { let (tx , mut rx) = tokio :: sync :: mpsc :: channel (1) ; let c = client . inner . clone () ; client . handle . spawn (async move { let eth_get_block_transaction_count_by_number_input = super :: types :: EthGetBlockTransactionCountByNumberInput :: from (eth_get_block_transaction_count_by_number_input) ; let params = jsonrpsee_core :: rpc_params ! [& eth_get_block_transaction_count_by_number_input . block_number] ; let resp : Result < super :: types :: EthGetBlockTransactionCountByNumberResult , _ > = c . request ("eth_getblocktransactioncountbynumber" , params) . await ; let _ = tx . send (resp) . await ; }) ; Ok (rx . blocking_recv () . unwrap () . map (Into :: into) ?) } # [allow (non_snake_case)] # [allow (clippy :: borrowed_box)] fn CallEth_GetCode (client : & Box < Client > , eth_get_code_input : EthGetCodeInput) -> Result < ffi :: EthGetCodeResult , Box < dyn std :: error :: Error >> { let (tx , mut rx) = tokio :: sync :: mpsc :: channel (1) ; let c = client . inner . clone () ; client . handle . spawn (async move { let eth_get_code_input = super :: types :: EthGetCodeInput :: from (eth_get_code_input) ; let params = jsonrpsee_core :: rpc_params ! [& eth_get_code_input . address , & eth_get_code_input . block_number] ; let resp : Result < super :: types :: EthGetCodeResult , _ > = c . request ("eth_getcode" , params) . await ; let _ = tx . send (resp) . await ; }) ; Ok (rx . blocking_recv () . unwrap () . map (Into :: into) ?) } # [allow (non_snake_case)] # [allow (clippy :: borrowed_box)] fn CallEth_GetStorageAt (client : & Box < Client > , eth_get_storage_at_input : EthGetStorageAtInput) -> Result < ffi :: EthGetStorageAtResult , Box < dyn std :: error :: Error >> { let (tx , mut rx) = tokio :: sync :: mpsc :: channel (1) ; let c = client . inner . clone () ; client . handle . spawn (async move { let eth_get_storage_at_input = super :: types :: EthGetStorageAtInput :: from (eth_get_storage_at_input) ; let params = jsonrpsee_core :: rpc_params ! [& eth_get_storage_at_input . address , & eth_get_storage_at_input . position , & eth_get_storage_at_input . block_number] ; let resp : Result < super :: types :: EthGetStorageAtResult , _ > = c . request ("eth_getstorageat" , params) . await ; let _ = tx . send (resp) . await ; }) ; Ok (rx . blocking_recv () . unwrap () . map (Into :: into) ?) }# [derive (Clone)] pub struct BlockchainService { # [allow (dead_code)] adapter : Arc < Handlers > } impl BlockchainService { # [inline] # [allow (dead_code)] pub fn new (adapter : Arc < Handlers >) -> BlockchainService { BlockchainService { adapter } } # [inline] # [allow (dead_code)] pub fn service (& self) -> blockchain_server :: BlockchainServer < BlockchainService > { blockchain_server :: BlockchainServer :: new (self . clone ()) } # [inline] # [allow (unused_mut , dead_code)] pub fn module (& self) -> Result < jsonrpsee_http_server :: RpcModule < () > , jsonrpsee_core :: Error > { let mut module = jsonrpsee_http_server :: RpcModule :: new (()) ; Ok (module) } } # [tonic :: async_trait] impl blockchain_server :: Blockchain for BlockchainService { # [allow (unused_variables)] async fn get_best_block_hash (& self , _request : tonic :: Request < () >) -> Result < tonic :: Response < super :: types :: BlockHashResult > , tonic :: Status > { unimplemented ! () ; } # [allow (unused_variables)] async fn get_block (& self , request : tonic :: Request < super :: types :: BlockInput >) -> Result < tonic :: Response < super :: types :: BlockResult > , tonic :: Status > { unimplemented ! () ; } }# [derive (Clone)] pub struct EthService { # [allow (dead_code)] adapter : Arc < Handlers > } impl EthService { # [inline] # [allow (dead_code)] pub fn new (adapter : Arc < Handlers >) -> EthService { EthService { adapter } } # [inline] # [allow (dead_code)] pub fn service (& self) -> eth_server :: EthServer < EthService > { eth_server :: EthServer :: new (self . clone ()) } # [inline] # [allow (unused_mut , dead_code)] pub fn module (& self) -> Result < jsonrpsee_http_server :: RpcModule < () > , jsonrpsee_core :: Error > { let mut module = jsonrpsee_http_server :: RpcModule :: new (()) ; let adapter = self . adapter . clone () ; module . register_method ("eth_accounts" , move | _params , _ | { Self :: Eth_Accounts (adapter . clone () ,) }) ? ; let adapter = self . adapter . clone () ; module . register_method ("eth_call" , move | _params , _ | { let mut eth_call_input = super :: types :: EthCallInput :: default () ; if _params . is_object () { eth_call_input = _params . parse () ? ; } else { let mut seq = _params . sequence () ; eth_call_input . transaction_info = seq . next () . map_err (| _ | missing_param ("transaction_info")) ? ; eth_call_input . block_number = seq . next () . map_err (| _ | missing_param ("block_number")) ? ; } let mut input = eth_call_input . into () ; Self :: Eth_Call (adapter . clone () , input) }) ? ; let adapter = self . adapter . clone () ; module . register_method ("eth_getbalance" , move | _params , _ | { let mut eth_get_balance_input = super :: types :: EthGetBalanceInput :: default () ; if _params . is_object () { eth_get_balance_input = _params . parse () ? ; } else { let mut seq = _params . sequence () ; eth_get_balance_input . address = seq . next () . map_err (| _ | missing_param ("address")) ? ; eth_get_balance_input . block_number = seq . next () . map_err (| _ | missing_param ("block_number")) ? ; } let mut input = eth_get_balance_input . into () ; Self :: Eth_GetBalance (adapter . clone () , input) }) ? ; let adapter = self . adapter . clone () ; module . register_method ("eth_getblockbyhash" , move | _params , _ | { let mut eth_get_block_by_hash_input = super :: types :: EthGetBlockByHashInput :: default () ; if _params . is_object () { eth_get_block_by_hash_input = _params . parse () ? ; } else { let mut seq = _params . sequence () ; eth_get_block_by_hash_input . hash = seq . next () . map_err (| _ | missing_param ("hash")) ? ; eth_get_block_by_hash_input . full_transaction = seq . next () . map_err (| _ | missing_param ("full_transaction")) ? ; } let mut input = eth_get_block_by_hash_input . into () ; Self :: Eth_GetBlockByHash (adapter . clone () , input) }) ? ; let adapter = self . adapter . clone () ; module . register_method ("eth_chainid" , move | _params , _ | { Self :: Eth_ChainId (adapter . clone () ,) }) ? ; let adapter = self . adapter . clone () ; module . register_method ("net_version" , move | _params , _ | { Self :: Net_Version (adapter . clone () ,) }) ? ; let adapter = self . adapter . clone () ; module . register_method ("eth_blocknumber" , move | _params , _ | { Self :: Eth_BlockNumber (adapter . clone () ,) }) ? ; let adapter = self . adapter . clone () ; module . register_method ("eth_getblockbynumber" , move | _params , _ | { let mut eth_get_block_by_number_input = super :: types :: EthGetBlockByNumberInput :: default () ; if _params . is_object () { eth_get_block_by_number_input = _params . parse () ? ; } else { let mut seq = _params . sequence () ; eth_get_block_by_number_input . number = seq . next () . map_err (| _ | missing_param ("number")) ? ; eth_get_block_by_number_input . full_transaction = seq . next () . map_err (| _ | missing_param ("full_transaction")) ? ; } let mut input = eth_get_block_by_number_input . into () ; Self :: Eth_GetBlockByNumber (adapter . clone () , input) }) ? ; let adapter = self . adapter . clone () ; module . register_method ("eth_gettransactionbyhash" , move | _params , _ | { let mut eth_get_transaction_by_hash_input = super :: types :: EthGetTransactionByHashInput :: default () ; if _params . is_object () { eth_get_transaction_by_hash_input = _params . parse () ? ; } else { let mut seq = _params . sequence () ; eth_get_transaction_by_hash_input . hash = seq . next () . map_err (| _ | missing_param ("hash")) ? ; } let mut input = eth_get_transaction_by_hash_input . into () ; Self :: Eth_GetTransactionByHash (adapter . clone () , input) }) ? ; let adapter = self . adapter . clone () ; module . register_method ("eth_gettransactionbyblockhashandindex" , move | _params , _ | { let mut eth_get_transaction_by_block_hash_and_index_input = super :: types :: EthGetTransactionByBlockHashAndIndexInput :: default () ; if _params . is_object () { eth_get_transaction_by_block_hash_and_index_input = _params . parse () ? ; } else { let mut seq = _params . sequence () ; eth_get_transaction_by_block_hash_and_index_input . block_hash = seq . next () . map_err (| _ | missing_param ("block_hash")) ? ; eth_get_transaction_by_block_hash_and_index_input . index = seq . next () . map_err (| _ | missing_param ("index")) ? ; } let mut input = eth_get_transaction_by_block_hash_and_index_input . into () ; Self :: Eth_GetTransactionByBlockHashAndIndex (adapter . clone () , input) }) ? ; let adapter = self . adapter . clone () ; module . register_method ("eth_gettransactionbyblocknumberandindex" , move | _params , _ | { let mut eth_get_transaction_by_block_number_and_index_input = super :: types :: EthGetTransactionByBlockNumberAndIndexInput :: default () ; if _params . is_object () { eth_get_transaction_by_block_number_and_index_input = _params . parse () ? ; } else { let mut seq = _params . sequence () ; eth_get_transaction_by_block_number_and_index_input . block_number = seq . next () . map_err (| _ | missing_param ("block_number")) ? ; eth_get_transaction_by_block_number_and_index_input . index = seq . next () . map_err (| _ | missing_param ("index")) ? ; } let mut input = eth_get_transaction_by_block_number_and_index_input . into () ; Self :: Eth_GetTransactionByBlockNumberAndIndex (adapter . clone () , input) }) ? ; let adapter = self . adapter . clone () ; module . register_method ("eth_mining" , move | _params , _ | { Self :: Eth_Mining (adapter . clone () ,) }) ? ; let adapter = self . adapter . clone () ; module . register_method ("eth_getblocktransactioncountbyhash" , move | _params , _ | { let mut eth_get_block_transaction_count_by_hash_input = super :: types :: EthGetBlockTransactionCountByHashInput :: default () ; if _params . is_object () { eth_get_block_transaction_count_by_hash_input = _params . parse () ? ; } else { let mut seq = _params . sequence () ; eth_get_block_transaction_count_by_hash_input . block_hash = seq . next () . map_err (| _ | missing_param ("block_hash")) ? ; } let mut input = eth_get_block_transaction_count_by_hash_input . into () ; Self :: Eth_GetBlockTransactionCountByHash (adapter . clone () , input) }) ? ; let adapter = self . adapter . clone () ; module . register_method ("eth_getblocktransactioncountbynumber" , move | _params , _ | { let mut eth_get_block_transaction_count_by_number_input = super :: types :: EthGetBlockTransactionCountByNumberInput :: default () ; if _params . is_object () { eth_get_block_transaction_count_by_number_input = _params . parse () ? ; } else { let mut seq = _params . sequence () ; eth_get_block_transaction_count_by_number_input . block_number = seq . next () . map_err (| _ | missing_param ("block_number")) ? ; } let mut input = eth_get_block_transaction_count_by_number_input . into () ; Self :: Eth_GetBlockTransactionCountByNumber (adapter . clone () , input) }) ? ; let adapter = self . adapter . clone () ; module . register_method ("eth_getcode" , move | _params , _ | { let mut eth_get_code_input = super :: types :: EthGetCodeInput :: default () ; if _params . is_object () { eth_get_code_input = _params . parse () ? ; } else { let mut seq = _params . sequence () ; eth_get_code_input . address = seq . next () . map_err (| _ | missing_param ("address")) ? ; eth_get_code_input . block_number = seq . next () . map_err (| _ | missing_param ("block_number")) ? ; } let mut input = eth_get_code_input . into () ; Self :: Eth_GetCode (adapter . clone () , input) }) ? ; let adapter = self . adapter . clone () ; module . register_method ("eth_getstorageat" , move | _params , _ | { let mut eth_get_storage_at_input = super :: types :: EthGetStorageAtInput :: default () ; if _params . is_object () { eth_get_storage_at_input = _params . parse () ? ; } else { let mut seq = _params . sequence () ; eth_get_storage_at_input . address = seq . next () . map_err (| _ | missing_param ("address")) ? ; eth_get_storage_at_input . position = seq . next () . map_err (| _ | missing_param ("position")) ? ; eth_get_storage_at_input . block_number = seq . next () . map_err (| _ | missing_param ("block_number")) ? ; } let mut input = eth_get_storage_at_input . into () ; Self :: Eth_GetStorageAt (adapter . clone () , input) }) ? ; Ok (module) } } # [tonic :: async_trait] impl eth_server :: Eth for EthService { async fn eth_accounts (& self , _request : tonic :: Request < () >) -> Result < tonic :: Response < super :: types :: EthAccountsResult > , tonic :: Status > { let adapter = self . adapter . clone () ; let result = tokio :: task :: spawn_blocking (move || { Self :: Eth_Accounts (adapter . clone () ,) . map_err (| e | tonic :: Status :: unknown (e . to_string ())) }) . await . map_err (| e | { tonic :: Status :: unknown (format ! ("failed to invoke RPC call: {}" , e)) }) ? ? ; Ok (tonic :: Response :: new (result . into ())) } async fn eth_call (& self , request : tonic :: Request < super :: types :: EthCallInput >) -> Result < tonic :: Response < super :: types :: EthCallResult > , tonic :: Status > { let adapter = self . adapter . clone () ; let result = tokio :: task :: spawn_blocking (move || { let input = request . into_inner () . into () ; Self :: Eth_Call (adapter . clone () , input) . map_err (| e | tonic :: Status :: unknown (e . to_string ())) }) . await . map_err (| e | { tonic :: Status :: unknown (format ! ("failed to invoke RPC call: {}" , e)) }) ? ? ; Ok (tonic :: Response :: new (result . into ())) } async fn eth_get_balance (& self , request : tonic :: Request < super :: types :: EthGetBalanceInput >) -> Result < tonic :: Response < super :: types :: EthGetBalanceResult > , tonic :: Status > { let adapter = self . adapter . clone () ; let result = tokio :: task :: spawn_blocking (move || { let input = request . into_inner () . into () ; Self :: Eth_GetBalance (adapter . clone () , input) . map_err (| e | tonic :: Status :: unknown (e . to_string ())) }) . await . map_err (| e | { tonic :: Status :: unknown (format ! ("failed to invoke RPC call: {}" , e)) }) ? ? ; Ok (tonic :: Response :: new (result . into ())) } async fn eth_get_block_by_hash (& self , request : tonic :: Request < super :: types :: EthGetBlockByHashInput >) -> Result < tonic :: Response < super :: types :: EthBlockInfo > , tonic :: Status > { let adapter = self . adapter . clone () ; let result = tokio :: task :: spawn_blocking (move || { let input = request . into_inner () . into () ; Self :: Eth_GetBlockByHash (adapter . clone () , input) . map_err (| e | tonic :: Status :: unknown (e . to_string ())) }) . await . map_err (| e | { tonic :: Status :: unknown (format ! ("failed to invoke RPC call: {}" , e)) }) ? ? ; Ok (tonic :: Response :: new (result . into ())) } # [allow (unused_variables)] async fn eth_send_transaction (& self , request : tonic :: Request < super :: types :: EthSendTransactionInput >) -> Result < tonic :: Response < super :: types :: EthSendTransactionResult > , tonic :: Status > { unimplemented ! () ; } async fn eth_chain_id (& self , _request : tonic :: Request < () >) -> Result < tonic :: Response < super :: types :: EthChainIdResult > , tonic :: Status > { let adapter = self . adapter . clone () ; let result = tokio :: task :: spawn_blocking (move || { Self :: Eth_ChainId (adapter . clone () ,) . map_err (| e | tonic :: Status :: unknown (e . to_string ())) }) . await . map_err (| e | { tonic :: Status :: unknown (format ! ("failed to invoke RPC call: {}" , e)) }) ? ? ; Ok (tonic :: Response :: new (result . into ())) } async fn net_version (& self , _request : tonic :: Request < () >) -> Result < tonic :: Response < super :: types :: EthChainIdResult > , tonic :: Status > { let adapter = self . adapter . clone () ; let result = tokio :: task :: spawn_blocking (move || { Self :: Net_Version (adapter . clone () ,) . map_err (| e | tonic :: Status :: unknown (e . to_string ())) }) . await . map_err (| e | { tonic :: Status :: unknown (format ! ("failed to invoke RPC call: {}" , e)) }) ? ? ; Ok (tonic :: Response :: new (result . into ())) } async fn eth_block_number (& self , _request : tonic :: Request < () >) -> Result < tonic :: Response < super :: types :: EthBlockNumberResult > , tonic :: Status > { let adapter = self . adapter . clone () ; let result = tokio :: task :: spawn_blocking (move || { Self :: Eth_BlockNumber (adapter . clone () ,) . map_err (| e | tonic :: Status :: unknown (e . to_string ())) }) . await . map_err (| e | { tonic :: Status :: unknown (format ! ("failed to invoke RPC call: {}" , e)) }) ? ? ; Ok (tonic :: Response :: new (result . into ())) } async fn eth_get_block_by_number (& self , request : tonic :: Request < super :: types :: EthGetBlockByNumberInput >) -> Result < tonic :: Response < super :: types :: EthBlockInfo > , tonic :: Status > { let adapter = self . adapter . clone () ; let result = tokio :: task :: spawn_blocking (move || { let input = request . into_inner () . into () ; Self :: Eth_GetBlockByNumber (adapter . clone () , input) . map_err (| e | tonic :: Status :: unknown (e . to_string ())) }) . await . map_err (| e | { tonic :: Status :: unknown (format ! ("failed to invoke RPC call: {}" , e)) }) ? ? ; Ok (tonic :: Response :: new (result . into ())) } async fn eth_get_transaction_by_hash (& self , request : tonic :: Request < super :: types :: EthGetTransactionByHashInput >) -> Result < tonic :: Response < super :: types :: EthTransactionInfo > , tonic :: Status > { let adapter = self . adapter . clone () ; let result = tokio :: task :: spawn_blocking (move || { let input = request . into_inner () . into () ; Self :: Eth_GetTransactionByHash (adapter . clone () , input) . map_err (| e | tonic :: Status :: unknown (e . to_string ())) }) . await . map_err (| e | { tonic :: Status :: unknown (format ! ("failed to invoke RPC call: {}" , e)) }) ? ? ; Ok (tonic :: Response :: new (result . into ())) } async fn eth_get_transaction_by_block_hash_and_index (& self , request : tonic :: Request < super :: types :: EthGetTransactionByBlockHashAndIndexInput >) -> Result < tonic :: Response < super :: types :: EthTransactionInfo > , tonic :: Status > { let adapter = self . adapter . clone () ; let result = tokio :: task :: spawn_blocking (move || { let input = request . into_inner () . into () ; Self :: Eth_GetTransactionByBlockHashAndIndex (adapter . clone () , input) . map_err (| e | tonic :: Status :: unknown (e . to_string ())) }) . await . map_err (| e | { tonic :: Status :: unknown (format ! ("failed to invoke RPC call: {}" , e)) }) ? ? ; Ok (tonic :: Response :: new (result . into ())) } async fn eth_get_transaction_by_block_number_and_index (& self , request : tonic :: Request < super :: types :: EthGetTransactionByBlockNumberAndIndexInput >) -> Result < tonic :: Response < super :: types :: EthTransactionInfo > , tonic :: Status > { let adapter = self . adapter . clone () ; let result = tokio :: task :: spawn_blocking (move || { let input = request . into_inner () . into () ; Self :: Eth_GetTransactionByBlockNumberAndIndex (adapter . clone () , input) . map_err (| e | tonic :: Status :: unknown (e . to_string ())) }) . await . map_err (| e | { tonic :: Status :: unknown (format ! ("failed to invoke RPC call: {}" , e)) }) ? ? ; Ok (tonic :: Response :: new (result . into ())) } async fn eth_mining (& self , _request : tonic :: Request < () >) -> Result < tonic :: Response < super :: types :: EthMiningResult > , tonic :: Status > { let adapter = self . adapter . clone () ; let result = tokio :: task :: spawn_blocking (move || { Self :: Eth_Mining (adapter . clone () ,) . map_err (| e | tonic :: Status :: unknown (e . to_string ())) }) . await . map_err (| e | { tonic :: Status :: unknown (format ! ("failed to invoke RPC call: {}" , e)) }) ? ? ; Ok (tonic :: Response :: new (result . into ())) } async fn eth_get_block_transaction_count_by_hash (& self , request : tonic :: Request < super :: types :: EthGetBlockTransactionCountByHashInput >) -> Result < tonic :: Response < super :: types :: EthGetBlockTransactionCountByHashResult > , tonic :: Status > { let adapter = self . adapter . clone () ; let result = tokio :: task :: spawn_blocking (move || { let input = request . into_inner () . into () ; Self :: Eth_GetBlockTransactionCountByHash (adapter . clone () , input) . map_err (| e | tonic :: Status :: unknown (e . to_string ())) }) . await . map_err (| e | { tonic :: Status :: unknown (format ! ("failed to invoke RPC call: {}" , e)) }) ? ? ; Ok (tonic :: Response :: new (result . into ())) } async fn eth_get_block_transaction_count_by_number (& self , request : tonic :: Request < super :: types :: EthGetBlockTransactionCountByNumberInput >) -> Result < tonic :: Response < super :: types :: EthGetBlockTransactionCountByNumberResult > , tonic :: Status > { let adapter = self . adapter . clone () ; let result = tokio :: task :: spawn_blocking (move || { let input = request . into_inner () . into () ; Self :: Eth_GetBlockTransactionCountByNumber (adapter . clone () , input) . map_err (| e | tonic :: Status :: unknown (e . to_string ())) }) . await . map_err (| e | { tonic :: Status :: unknown (format ! ("failed to invoke RPC call: {}" , e)) }) ? ? ; Ok (tonic :: Response :: new (result . into ())) } async fn eth_get_code (& self , request : tonic :: Request < super :: types :: EthGetCodeInput >) -> Result < tonic :: Response < super :: types :: EthGetCodeResult > , tonic :: Status > { let adapter = self . adapter . clone () ; let result = tokio :: task :: spawn_blocking (move || { let input = request . into_inner () . into () ; Self :: Eth_GetCode (adapter . clone () , input) . map_err (| e | tonic :: Status :: unknown (e . to_string ())) }) . await . map_err (| e | { tonic :: Status :: unknown (format ! ("failed to invoke RPC call: {}" , e)) }) ? ? ; Ok (tonic :: Response :: new (result . into ())) } async fn eth_get_storage_at (& self , request : tonic :: Request < super :: types :: EthGetStorageAtInput >) -> Result < tonic :: Response < super :: types :: EthGetStorageAtResult > , tonic :: Status > { let adapter = self . adapter . clone () ; let result = tokio :: task :: spawn_blocking (move || { let input = request . into_inner () . into () ; Self :: Eth_GetStorageAt (adapter . clone () , input) . map_err (| e | tonic :: Status :: unknown (e . to_string ())) }) . await . map_err (| e | { tonic :: Status :: unknown (format ! ("failed to invoke RPC call: {}" , e)) }) ? ? ; Ok (tonic :: Response :: new (result . into ())) } }