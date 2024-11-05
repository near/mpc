use std::collections::VecDeque;
use std::future::Future;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;
use tokio::task_local;

struct WeakCollection<T> {
    buffers: [VecDeque<Weak<T>>; 2],
    current: usize,
}

impl<T> WeakCollection<T> {
    fn new() -> Self {
        Self {
            buffers: [VecDeque::new(), VecDeque::new()],
            current: 0,
        }
    }

    fn push(&mut self, item: Weak<T>) {
        self.buffers[self.current].push_back(item);
        self.refresh();
    }

    fn refresh(&mut self) {
        for _ in 0..2 {
            match self.buffers[self.current].pop_front() {
                Some(item) => {
                    if item.strong_count() > 0 {
                        self.buffers[1 - self.current].push_back(item);
                    }
                }
                None => {
                    self.current = 1 - self.current;
                    continue;
                }
            }
        }
    }

    fn iter(&self) -> impl Iterator<Item = Arc<T>> + '_ {
        self.buffers[1 - self.current]
            .iter()
            .chain(self.buffers[self.current].iter())
            .filter_map(|weak| weak.upgrade())
    }
}

pub struct TaskHandle {
    _parent: Option<Arc<TaskHandle>>, // This is needed to keep the parent alive
    children: Mutex<WeakCollection<TaskHandle>>,
    description: String,
    start_time: Instant,
    progress: Mutex<String>,
    finished: AtomicBool,
}

struct TaskHandleScoped(Arc<TaskHandle>);

impl Drop for TaskHandleScoped {
    fn drop(&mut self) {
        self.0
            .finished
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

task_local! {
    static CURRENT_TASK: Arc<TaskHandleScoped>;
}

impl TaskHandle {
    pub fn set_progress(&self, progress: &str) {
        let mut progress_lock = self.progress.lock().unwrap();
        *progress_lock = progress.to_string();
    }

    fn new_child(self: &Arc<TaskHandle>, description: &str) -> Arc<TaskHandle> {
        let description = description.to_string();
        let progress = Mutex::new("".to_string());
        let handle = Arc::new(TaskHandle {
            _parent: Some(self.clone()),
            children: Mutex::new(WeakCollection::new()),
            description,
            start_time: Instant::now(),
            progress,
            finished: AtomicBool::new(false),
        });
        self.children.lock().unwrap().push(Arc::downgrade(&handle));
        handle
    }

    pub fn report(&self) -> TaskStatusReport {
        let children_handles = self.children.lock().unwrap().iter().collect::<Vec<_>>();
        let children_reports = children_handles
            .into_iter()
            .map(|child| child.report())
            .collect();
        TaskStatusReport {
            description: self.description.clone(),
            progress: self.progress.lock().unwrap().clone(),
            elapsed: self.start_time.elapsed(),
            finished: self.finished.load(std::sync::atomic::Ordering::Relaxed),
            children: children_reports,
        }
    }
}

pub fn spawn<F, R>(description: &str, f: F) -> tokio::task::JoinHandle<R>
where
    F: Future<Output = R> + Send + 'static,
    R: Send + 'static,
{
    let current_task = CURRENT_TASK.get();
    let handle = current_task.0.new_child(description);
    tokio::spawn(CURRENT_TASK.scope(Arc::new(TaskHandleScoped(handle)), f))
}

pub fn set_progress(progress: &str) {
    CURRENT_TASK.with(|task| task.0.set_progress(progress));
}

pub fn start_root_task<F, R>(f: F) -> (impl Future<Output = R>, Arc<TaskHandle>)
where
    F: Future<Output = R> + Send + 'static,
    R: Send + 'static,
{
    let handle = Arc::new(TaskHandle {
        _parent: None,
        children: Mutex::new(WeakCollection::new()),
        description: "root".to_string(),
        start_time: Instant::now(),
        progress: Mutex::new("".to_string()),
        finished: AtomicBool::new(false),
    });
    (
        CURRENT_TASK.scope(Arc::new(TaskHandleScoped(handle.clone())), f),
        handle,
    )
}

pub fn current_task_name() -> String {
    CURRENT_TASK.get().0.description.clone()
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TaskStatusReport {
    description: String,
    progress: String,
    elapsed: std::time::Duration,
    finished: bool,
    children: Vec<TaskStatusReport>,
}

#[cfg(test)]
pub mod testing {
    pub fn start_root_task_with_periodic_dump<F, R>(f: F) -> impl std::future::Future<Output = R>
    where
        F: std::future::Future<Output = R> + Send + 'static,
        R: Send + 'static,
    {
        let (future, handle) = super::start_root_task(f);
        let handle_clone = handle.clone();
        tokio::spawn(async move {
            loop {
                let report = handle_clone.report();
                pretty_print_report(report);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
        future
    }

    fn pretty_print_report(report: super::TaskStatusReport) {
        fn pretty_print_report_inner(report: super::TaskStatusReport, indent: usize) {
            println!(
                "{}[{}] {:>3} {}: {}",
                " ".repeat(indent),
                if report.finished { "✔" } else { " " },
                format_duration(report.elapsed),
                report.description,
                report.progress
            );
            for child in report.children {
                pretty_print_report_inner(child, indent + 2);
            }
        }
        println!("Current tasks:");
        pretty_print_report_inner(report, 2);
    }

    fn format_duration(duration: std::time::Duration) -> String {
        if duration.as_secs() > 60 {
            format!("{}m", duration.as_secs() / 60)
        } else if duration.as_secs() >= 1 {
            format!("{}s", duration.as_secs())
        } else {
            "<1s".to_string()
        }
    }
}
