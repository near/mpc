// TODO(#398): remove once the graph has a consumer.
#[cfg_attr(not(test), expect(dead_code, reason = "the graph has no consumer yet"))]
#[expect(unused_imports, reason = "the graph has no consumer yet")]
mod graph;
