use std::net::SocketAddr;
use std::pin::Pin;

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

// Include the generated protobuf code (produced by build.rs).
pub mod proto {
    tonic::include_proto!("echo");
}

use proto::{
    echo_server::{Echo, EchoServer},
    Chunk, EchoReq, EchoResp, StreamReq,
};

#[derive(Default)]
pub struct EchoService;

#[tonic::async_trait]
impl Echo for EchoService {
    async fn echo(&self, req: Request<EchoReq>) -> Result<Response<EchoResp>, Status> {
        let message = req.into_inner().message;
        Ok(Response::new(EchoResp { message }))
    }

    type StreamStream = Pin<Box<dyn tokio_stream::Stream<Item = Result<Chunk, Status>> + Send>>;

    async fn stream(
        &self,
        req: Request<StreamReq>,
    ) -> Result<Response<Self::StreamStream>, Status> {
        let count = req.into_inner().count.min(10); // cap at 10 for safety
        let chunks: Vec<Result<Chunk, Status>> = (0..count)
            .map(|i| {
                Ok(Chunk {
                    seq: i,
                    data: format!("chunk-{i}"),
                })
            })
            .collect();

        let stream = tokio_stream::iter(chunks);
        Ok(Response::new(Box::pin(stream)))
    }
}

/// Spawns a tonic gRPC server on an OS-assigned port.
pub async fn spawn_grpc_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = TcpListenerStream::new(listener);

    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(EchoServer::new(EchoService::default()))
            .serve_with_incoming(incoming)
            .await
            .ok();
    });

    addr
}
