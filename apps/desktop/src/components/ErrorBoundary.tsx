import { Component, createRef, type ErrorInfo, type ReactNode } from 'react';

interface Props { children: ReactNode }
interface State { failed: boolean }

export class ErrorBoundary extends Component<Props, State> {
  state: State = { failed: false };
  private readonly headingRef = createRef<HTMLHeadingElement>();
  static getDerivedStateFromError(): State { return { failed: true }; }
  componentDidCatch(_error: unknown, _info: ErrorInfo): void { /* 技术详情不写日志、不进入 DOM。 */ }
  componentDidUpdate(_previousProps: Props, previousState: State): void {
    if (!previousState.failed && this.state.failed) this.headingRef.current?.focus();
  }
  private recover = () => {
    this.setState({ failed: false }, () => document.getElementById('main-content')?.focus());
  };
  render() {
    if (!this.state.failed) return this.props.children;
    return <main className="fatal-boundary" role="alert" aria-live="assertive"><h1 ref={this.headingRef} tabIndex={-1}>界面暂时不可用 / Interface unavailable</h1><p>未显示技术详情。可安全返回工作台并重试。</p><button type="button" onClick={this.recover}>返回工作台 / Return to dashboard</button></main>;
  }
}
