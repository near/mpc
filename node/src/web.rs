use crate::config::WebUIConfig;
use crate::tracking::TaskHandle;
use actix_web::{get, web};
use std::sync::Arc;

#[get("/debug/tasks")]
async fn debug(root_task_handle: web::Data<Arc<TaskHandle>>) -> String {
    format!("{:?}", root_task_handle.report())
}

pub async fn run_web_server(
    root_task_handle: Arc<TaskHandle>,
    config: WebUIConfig,
) -> anyhow::Result<()> {
    let server = actix_web::HttpServer::new(move || {
        actix_web::App::new()
            .app_data(web::Data::new(root_task_handle.clone()))
            .service(debug)
    })
    .bind(format!("{}:{}", config.host, config.port))?
    .run();
    server.await?;
    Ok(())
}
