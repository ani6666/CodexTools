use tauri::Runtime;

pub trait MainWindowActivation {
    fn show(&self) -> Result<(), ()>;
    fn unminimize(&self) -> Result<(), ()>;
    fn focus(&self) -> Result<(), ()>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MainWindowActivationReport {
    pub show_succeeded: bool,
    pub unminimize_succeeded: bool,
    pub focus_succeeded: bool,
}

pub fn activate_main_window(activation: &dyn MainWindowActivation) -> MainWindowActivationReport {
    let show_succeeded = activation.show().is_ok();
    let unminimize_succeeded = activation.unminimize().is_ok();
    let focus_succeeded = activation.focus().is_ok();
    MainWindowActivationReport {
        show_succeeded,
        unminimize_succeeded,
        focus_succeeded,
    }
}

pub struct TauriMainWindowActivation<R: Runtime>(pub tauri::WebviewWindow<R>);

impl<R: Runtime> MainWindowActivation for TauriMainWindowActivation<R> {
    fn show(&self) -> Result<(), ()> {
        self.0.show().map_err(|_| ())
    }

    fn unminimize(&self) -> Result<(), ()> {
        self.0.unminimize().map_err(|_| ())
    }

    fn focus(&self) -> Result<(), ()> {
        self.0.set_focus().map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    struct RecordingActivation {
        calls: Mutex<Vec<&'static str>>,
    }

    impl MainWindowActivation for RecordingActivation {
        fn show(&self) -> Result<(), ()> {
            self.calls.lock().unwrap().push("show");
            Err(())
        }

        fn unminimize(&self) -> Result<(), ()> {
            self.calls.lock().unwrap().push("unminimize");
            Ok(())
        }

        fn focus(&self) -> Result<(), ()> {
            self.calls.lock().unwrap().push("focus");
            Err(())
        }
    }

    #[test]
    fn activation_attempts_fixed_sequence_and_absorbs_each_failure() {
        let activation = RecordingActivation {
            calls: Mutex::new(Vec::new()),
        };
        let report = activate_main_window(&activation);
        assert_eq!(
            activation.calls.lock().unwrap().as_slice(),
            ["show", "unminimize", "focus"]
        );
        assert_eq!(
            report,
            MainWindowActivationReport {
                show_succeeded: false,
                unminimize_succeeded: true,
                focus_succeeded: false,
            }
        );
    }
}
