# Third party license notices
This folder holds third party license notices generated with `cargo about`.

### Why?
Many open source licenses require us to include their license text and copyright notices when we distribute software that uses their code.

### How to re-generate:
1. Install [cargo about](https://github.com/EmbarkStudios/cargo-about).
2. From this folder, run `cargo about generate -m ../Cargo.lock about.hbs > licenses.html`.

### Web server integration
The `licenses.html` file is automatically served by the MPC node web server at the `/licenses` endpoint. This ensures that third-party license information is accessible to users for compliance purposes when running the node.
