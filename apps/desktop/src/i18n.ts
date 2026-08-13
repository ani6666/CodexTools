export const FALLBACK_LOCALE = 'zh-CN' as const;
export const SUPPORTED_LOCALES = ['zh-CN', 'en'] as const;
export type SupportedLocale = (typeof SUPPORTED_LOCALES)[number];

const zhCN = {
  'app.name': 'CodexTools',
  'a11y.skipToContent': '跳到主要内容',
  'nav.label': '主导航',
  'nav.overview': '概览',
  'nav.statusLab': '状态样本',
  'nav.preferences': '偏好设置',
  'shell.eyebrow': '桌面工作区',
  'shell.title': '本地身份工作台',
  'shell.subtitle': '应用壳与安全边界已就绪。身份管理流程将在后续阶段接入。',
  'shell.stage': 'M3.2 壳层',
  'overview.title': '工作区概览',
  'overview.description': '当前页面只展示界面基础设施，不读取本地身份或凭据。',
  'overview.boundaryTitle': '安全边界',
  'overview.boundaryBody': '无自动扫描、无网络请求、无秘密正文进入前端。',
  'overview.languageTitle': '界面语言',
  'overview.languageBody': '默认跟随系统，可随时在偏好设置中切换。',
  'overview.contractTitle': '合同状态',
  'overview.contractBody': 'M3.1 typed contract 已就绪，本阶段不调用 IPC。',
  'status.title': '界面状态样本',
  'status.description': '这些是本地 fixture，用于验证展示状态，不代表真实业务操作。',
  'status.selectorLabel': '选择演示状态',
  'state.ready.title': '准备就绪',
  'state.ready.body': '壳层可以继续承载后续功能。',
  'state.empty.title': '暂无内容',
  'state.empty.body': '当前没有可展示的 fixture 条目。',
  'state.loading.title': '正在加载',
  'state.loading.body': '正在准备本地演示状态。',
  'state.error.title': '出现错误',
  'state.error.body': '演示请求未完成，请检查后重试。',
  'state.cancelled.title': '操作已取消',
  'state.cancelled.body': '演示操作已在可取消点停止。',
  'state.duplicate.title': '重复操作',
  'state.duplicate.body': '相同操作已经存在，无需重复提交。',
  'state.compatibility_protected.title': '兼容性保护',
  'state.compatibility_protected.body': '当前状态受保护，需要确认兼容性后继续。',
  'preferences.title': '偏好设置',
  'preferences.description': '设置仅保存在当前设备的浏览器存储中。',
  'preferences.languageLabel': '界面语言',
  'preferences.languageHint': '更改后立即应用到整个应用壳。',
  'locale.system': '跟随系统',
  'locale.zhCN': '简体中文',
  'locale.en': 'English',
  'action.previewNotification': '预览通知',
  'action.dismiss': '关闭',
  'notification.fixture': '这是一条本地演示通知。',
  'notification.region': '全局通知',
  'footer.boundary': '仅本地壳层 fixture · 未连接业务数据',
} as const;

type MessageKey = keyof typeof zhCN;

const en: Record<MessageKey, string> = {
  'app.name': 'CodexTools',
  'a11y.skipToContent': 'Skip to main content',
  'nav.label': 'Primary navigation',
  'nav.overview': 'Overview',
  'nav.statusLab': 'State samples',
  'nav.preferences': 'Preferences',
  'shell.eyebrow': 'Desktop workspace',
  'shell.title': 'Local identity workspace',
  'shell.subtitle': 'The application shell and safety boundaries are ready. Identity workflows arrive in a later stage.',
  'shell.stage': 'M3.2 shell',
  'overview.title': 'Workspace overview',
  'overview.description': 'This view only demonstrates interface foundations. It does not read local identities or credentials.',
  'overview.boundaryTitle': 'Safety boundary',
  'overview.boundaryBody': 'No automatic scans, network requests, or secret material in the frontend.',
  'overview.languageTitle': 'Interface language',
  'overview.languageBody': 'Follows the system by default and can be changed in Preferences.',
  'overview.contractTitle': 'Contract status',
  'overview.contractBody': 'The M3.1 typed contract is ready. This stage does not invoke IPC.',
  'status.title': 'Interface state samples',
  'status.description': 'These local fixtures verify display states and do not represent real operations.',
  'status.selectorLabel': 'Choose a sample state',
  'state.ready.title': 'Ready',
  'state.ready.body': 'The shell is ready to host later capabilities.',
  'state.empty.title': 'Nothing here yet',
  'state.empty.body': 'There are no fixture items to display.',
  'state.loading.title': 'Loading',
  'state.loading.body': 'Preparing the local sample state.',
  'state.error.title': 'Something went wrong',
  'state.error.body': 'The sample request did not complete. Review it and try again.',
  'state.cancelled.title': 'Operation cancelled',
  'state.cancelled.body': 'The sample operation stopped at a cancellable point.',
  'state.duplicate.title': 'Duplicate operation',
  'state.duplicate.body': 'The same operation already exists and does not need to be submitted again.',
  'state.compatibility_protected.title': 'Compatibility protected',
  'state.compatibility_protected.body': 'This state is protected until compatibility is confirmed.',
  'preferences.title': 'Preferences',
  'preferences.description': 'Settings are stored only in browser storage on this device.',
  'preferences.languageLabel': 'Interface language',
  'preferences.languageHint': 'Changes apply to the entire application shell immediately.',
  'locale.system': 'Follow system',
  'locale.zhCN': '简体中文',
  'locale.en': 'English',
  'action.previewNotification': 'Preview notification',
  'action.dismiss': 'Dismiss',
  'notification.fixture': 'This is a local demonstration notification.',
  'notification.region': 'Global notifications',
  'footer.boundary': 'Local shell fixture only · No business data connected',
};

const resources: Record<SupportedLocale, Record<MessageKey, string>> = { 'zh-CN': zhCN, en };

export function detectSystemLocale(languages: readonly string[] = navigator.languages): SupportedLocale {
  for (const language of languages) {
    const normalized = language.toLowerCase();
    if (normalized.startsWith('zh')) return 'zh-CN';
    if (normalized.startsWith('en')) return 'en';
  }
  return FALLBACK_LOCALE;
}

export function translate(locale: SupportedLocale, key: string): string {
  const fallback = resources[FALLBACK_LOCALE] as Record<string, string>;
  return (resources[locale] as Record<string, string>)[key] ?? fallback[key] ?? key;
}

export function translateFromResources(
  localeMessages: Readonly<Record<string, string>>,
  fallbackMessages: Readonly<Record<string, string>>,
  key: string,
): string {
  return localeMessages[key] ?? fallbackMessages[key] ?? key;
}

export type { MessageKey };
