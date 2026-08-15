export type EventChannelState = 'ready' | 'unavailable';
export type OperationStatusUnlisten = () => void | Promise<void>;

function releaseSafely(release: OperationStatusUnlisten): void {
  try {
    void Promise.resolve(release()).catch(() => undefined);
  } catch {
    // 清理失败只影响事件更新通道，不得泄漏运行时错误或形成未处理拒绝。
  }
}

export function superviseOperationStatusListener(
  register: () => Promise<OperationStatusUnlisten>,
  onState: (state: EventChannelState) => void,
): () => void {
  let disposed = false;
  let release: OperationStatusUnlisten | undefined;

  void register().then(
    (registeredRelease) => {
      if (disposed) {
        releaseSafely(registeredRelease);
        return;
      }
      release = registeredRelease;
      onState('ready');
    },
    () => {
      if (!disposed) onState('unavailable');
    },
  );

  return () => {
    disposed = true;
    if (release) {
      releaseSafely(release);
      release = undefined;
    }
  };
}
