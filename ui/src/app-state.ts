import type { ConnectionPreset } from './catalog';
import { LOCAL_BROKER } from './broker';
import type { HostKeyCandidate } from './connection-input';
import type {
  ActivityEntry,
  Approval,
  AwsProfileList,
  BrokerProfile,
  ConnectionSummary,
  ConnectionType,
  ElicitationRequest,
  IdentityInfo,
  IssuedEndpoint,
  McpAuthDraft,
  McpAuthState,
  McpStatusReport,
  McpToolInfo,
  LockState,
  NotificationSettings,
  OnePasswordField,
  OnePasswordIntegration,
  OnePasswordItem,
  OnePasswordVault,
  RequestRecord,
  SecretKind,
  SecretOrigin,
  SecretSummary,
  SessionSummary,
  Settings,
  TestErrorKind,
} from './types';
import {
  getBrokerQueryData,
  removeBrokerQueryData,
  setBrokerQueryData,
} from './query-client';
import { readSamplesDismissed } from './samples';
import { UiStore } from './ui-store';

export const TABS = ['secrets', 'connections', 'start', 'activity'] as const;
export type Tab = typeof TABS[number];
/** The tray has no tab switcher: Tools ride above Credentials in one view,
 * and Activity sits behind the header toggle. 'connections' is a
 * window-only tab. */
export const DROPDOWN_TABS = ['secrets', 'activity'] as const satisfies readonly Tab[];

/** Settings is the one sheet that both app chromes can open independently. */
export type SettingsSurface = 'desktop' | 'menubar';

/** The Credentials page's sidebar-tile filter scopes. The tile presentation
 * (labels, icons, order) lives with the view in app.tsx. */
// 'connections' scopes the unified inventory to tools; the rest scope the
// credentials inside it.
export type SecretCategory =
  'all' | 'connections' | 'passwords' | 'secrets' | 'codes' | 'onepassword';

export interface SheetState {
  kind: 'add-secret' | 'edit-secret' | 'add-conn' | 'edit-conn' | 'settings'
    | 'clear-activity' | 'elicitation' | 'approval' | 'mcp-auth' | 'wiring-tools'
    | 'endpoint-issued' | 'onepassword';
  id?: string;
  /** A focused edit-secret variant: the password detail pane's Change
   * Password… and Set Up Code… flows open the same sheet narrowed to that
   * one field, Passwords-style. */
  focus?: 'value' | 'totp';
  expectedUpdatedAt?: string;
  endpoint?: IssuedEndpoint;
}

export type OnePasswordMethod = 'desktop_app' | 'service_account' | 'connect';

export interface OnePasswordFieldSelection {
  key: string;
  vault: OnePasswordVault;
  item: OnePasswordItem;
  field: OnePasswordField;
  alias: string;
}

export interface OnePasswordFlowState {
  intent: 'create' | 'browse' | 'update';
  step: 1 | 2 | 3;
  method: OnePasswordMethod;
  label: string;
  account: string;
  connectUrl: string;
  token: string;
  integration: OnePasswordIntegration | null;
  vaults: OnePasswordVault[];
  vault: OnePasswordVault | null;
  items: OnePasswordItem[];
  item: OnePasswordItem | null;
  fields: OnePasswordField[];
  selections: Record<string, OnePasswordFieldSelection>;
  busy: boolean;
  error: string | null;
}

export interface ConfirmState {
  kind: string;
  id?: string | number;
  name?: string;
}

export interface ConnectionDraft {
  name?: string;
  nameIsAutomatic?: boolean;
  value?: string;
  /** Whether the masked value in an edit-secret sheet was actually changed. */
  secretValueModified?: boolean;
  /** Whether the credential value field is currently rendered as plain text. */
  showCredentialValue?: boolean;
  /** The password generator recipe selected from its split-button menu. */
  passwordGenerationFormat?: 'strong' | 'no-special' | 'easy-to-type';
  /** The add-credential sheet's type segment. */
  secretKind?: SecretKind;
  /** The edit-secret sheet's group choice (Secrets / Connection
   * Secrets). Distinct from `origin` below, which belongs to connection
   * drafts. */
  secretOrigin?: SecretOrigin;
  /** Password fields (kind 'password'). */
  site?: string;
  username?: string;
  /** Raw 2FA seed input (write-only, like value). */
  totp?: string;
  /** Whether the masked 2FA input was filled by decoding a QR-code image
   * (the input stays masked, so this backs the only visible confirmation). */
  totpFromQrImage?: boolean;
  /** Whether a chosen QR-code image is still being decoded. */
  totpQrImageScanning?: boolean;
  /** Where the last 2FA image came from (file picker vs screen capture). */
  totpQrSource?: 'file' | 'screen';
  /** Object URL of the last captured/chosen image, for the failure preview. */
  totpQrPreviewUrl?: string;
  /** Show “Open Settings” after a Screen Recording permission denial. */
  totpCaptureNeedsSettings?: boolean;
  /** The edit sheet's explicit "remove 2FA" choice. */
  removeTotp?: boolean;
  importWarnings?: string[];
  origin?: string | null;
  isMcp?: boolean;
  entryId?: string;
  mcpPath?: string | null;
  scheme?: string | null;
  host?: string | null;
  port?: string;
  dbname?: string | null;
  user?: string | null;
  hostKeyFingerprint?: string | null;
  hostKeyCandidates?: HostKeyCandidate[];
  hostKeyCheckMessage?: string;
  hostKeyChecking?: boolean;
  hostKeyAutoPinned?: boolean;
  proxyJump?: string | null;
  sslmode?: string | null;
  sslmodeIsAutomatic?: boolean;
  pgCaBundlePath?: string | null;
  testPath?: string | null;
  url?: string | null;
  template?: string | null;
  /**
   * Last non-empty API template managed by the credential chooser. Kept while
   * "None" is selected so choosing another credential can restore the
   * original header/query shape instead of assuming Bearer authentication.
   */
  apiCredentialTemplate?: string | null;
  /** Credential reference currently named by apiCredentialTemplate. */
  apiCredentialName?: string | null;
  secretId?: string | null;
  secretSource?: 'existing' | 'new' | 'none';
  newSecretName?: string;
  newSecretValue?: string;
  importedCredential?: string | null;
  identityFile?: string;
  keyPassphrase?: string;
  identityFiles?: string[];
  sshImportId?: string;
  destination?: string | null;
  authMode?: string;
  // AWS SigV4 signer fields (authMode 'sigv4'): coordinates plus vault
  // credential references picked from the saved-secrets list.
  signerRegion?: string;
  signerService?: string;
  signerAccessKeyRef?: string | null;
  signerSecretKeyRef?: string | null;
  signerSessionTokenRef?: string | null;
  // GCP service-account signer fields (authMode 'gcp').
  signerGcpKeyRef?: string | null;
  signerGcpScope?: string;
  // Cloud CLI setup. Provider coordinates are ordinary metadata; credential
  // values are write-only and become vault items in the atomic add request.
  cloudProvider?: 'aws' | 'gcp' | 'azure';
  cloudRegion?: string;
  cloudAccessKeyRef?: string | null;
  cloudAccessKeyValue?: string;
  cloudSecretKeyRef?: string | null;
  cloudSecretKeyValue?: string;
  cloudSessionTokenRef?: string | null;
  cloudSessionTokenValue?: string;
  cloudRoleArn?: string;
  cloudExternalId?: string;
  cloudTenantId?: string;
  cloudClientId?: string;
  cloudClientSecretRef?: string | null;
  cloudClientSecretValue?: string;
  cloudSubscriptionId?: string;
  cloudGcpKeyRef?: string | null;
  cloudGcpKeyValue?: string;
  cloudProject?: string;
  cloudScope?: string;
  cloudSessionTtl?: string;
  cloudCredentialSources?: Record<string, 'existing' | 'new' | 'none'>;
  // Guided cloud setup (add flow only). The one-shot form remains reachable
  // via Skip; everything the wizard captures lands in the fields above.
  cloudSetupStep?: number;
  cloudSetupPath?: 'script' | 'console' | 'reuse';
  /** Reuse: the local ~/.aws profile to mint from, and the AWS-enforced
   * leash bounding every minted session. */
  cloudSourceProfile?: string;
  cloudSourceOrigin?: string;
  cloudSourceOriginLabel?: string;
  cloudAttenuation?: string;
  cloudSetupSkipped?: boolean;
  cloudScriptRole?: string;
  cloudPasteRaw?: string;
  cloudPasteSource?: string | null;
  // Upstream mTLS paths (Advanced section), both-or-neither.
  clientCertPath?: string | null;
  clientKeyPath?: string | null;
  oauthClientId?: string;
  oauthClientSecret?: string;
  oauthAuthUrl?: string;
  oauthTokenUrl?: string;
  oauthScopes?: string[];
  authDetail?: string;
  import?: string;
  setupSource?: 'manual' | 'import';
}

export interface ConnectionReadyState {
  name: string;
}

export interface RemoteSetupState {
  open: boolean;
  advancedOpen: boolean;
  url: string;
  /** The legacy management token, under Advanced while it is retired. */
  token: string;
  /** What this Mac will be called in the broker's device list. Prefilled
   * from the computer name, editable because "MacBook Pro" is not a name
   * you can pick out of a list of four. */
  deviceName: string;
  busy: boolean;
  /** A passkey sign-in is waiting on the system browser. Distinct from
   * `busy`: it can take a minute and the user is looking at another
   * window, so the pane says so rather than appearing hung. */
  signingIn: boolean;
  error: string | null;
}

export interface ConnMenuPoint {
  x: number;
  y: number;
}

export type LoadKey = 'secrets' | 'connections' | 'identity' | 'sessions' | 'activity'
  | 'settings' | 'elicitations' | 'approvals' | 'requests';

export interface LoadStatus {
  status: 'idle' | 'loading' | 'ready' | 'error';
  error?: string;
}

export interface WiringToolsState {
  connectionId: string;
  connectionName: string;
  loading: boolean;
  error?: string;
  tools?: McpToolInfo[];
  stale?: boolean;
  fetchedAt?: string;
  cacheAgeSeconds?: number;
  truncated?: boolean;
  selected: string[] | null;
  saving: boolean;
}

export interface McpStatusState {
  running: boolean;
  report?: McpStatusReport;
  error?: string;
}

export interface ConnectionTestState {
  running: boolean;
  ok?: boolean;
  detail?: string;
  kind?: TestErrorKind;
}

export interface AppState {
  tab: Tab;
  broker: BrokerProfile;
  brokerMenuOpen: boolean;
  remoteSetup: RemoteSetupState;
  localUsername: string;
  secrets: SecretSummary[];
  onepasswordIntegrations: OnePasswordIntegration[];
  onepasswordFlow: OnePasswordFlowState | null;
  connections: ConnectionSummary[];
  /** Local ~/.aws profiles for the cloud reuse picker: null until read,
   * since it is fetched lazily when that path is first chosen. */
  awsProfiles: AwsProfileList | null;
  identity: IdentityInfo | null;
  sessions: SessionSummary[];
  activity: ActivityEntry[];
  activityNextBefore: number | null;
  activityLoadingOlder: boolean;
  activityOlderError: string | null;
  elicitations: ElicitationRequest[];
  elicitValues: Record<string, string>;
  approvals: Approval[];
  requests: RequestRecord[];
  /** The local broker is starting after a pick (chooser or switcher), so
   * both surfaces can disable their controls for the duration. */
  brokerStartingLocal: boolean;
  approvalAnswering: string | null;
  approvalHostKeyProvenance: {
    approvalId: string;
    loading: boolean;
    candidates: HostKeyCandidate[];
    revokedFingerprints: string[];
    hasCertificateAuthority: boolean;
    error?: string;
  } | null;
  agentSetupInstructions: string;
  settings: Settings;
  notificationSettings: NotificationSettings;
  /** The app lock: state and settings, mirrored from the Rust side. */
  lock: LockState;
  /** True while the system authentication sheet is up. */
  unlocking: boolean;
  /** A failed unlock's message, shown under the prompt until the next try. */
  unlockError: string;
  launchAtLogin: boolean;
  loadStatus: Record<LoadKey, LoadStatus>;
  /** Secret id → the value currently on screen. Held only for as long as the
   * reveal lasts: unrevealing, changing tab or losing the window drops it. */
  reveal: Record<string, string>;
  epExpanded: Record<string, boolean>;
  epMenuOpen: string | null;
  /** ⋯ menu on the Connect section label (renew / rotate / revoke address). */
  epOptsMenuOpen: string | null;
  sshSockets: Record<string, string>;
  /** Per-chrome visibility keeps an open desktop Settings sheet from also
   * appearing in the menu-bar window, and vice versa. */
  settingsSheetOpen: Record<SettingsSurface, boolean>;
  sheet: SheetState | null;
  draft: ConnectionDraft;
  sheetErrors: Record<string, string>;
  sheetBaseline: string | null;
  confirmDiscard: boolean;
  formMenuOpen: string | null;
  connAdvancedOpen: boolean;
  connDetailAdvancedOpen: string | null;
  /** Per-connection open state for the Details disclosure under Advanced. */
  connDetailDetailsOpen: string | null;
  connType: ConnectionType;
  connEntryName: string | null;
  connPreset: ConnectionPreset | null;
  confirm: ConfirmState | null;
  toolSearch: string;
  secretSearch: string;
  /** The Credentials page's active category tile. */
  secretCategory: SecretCategory;
  /** Credential shown in the detail inspector; falls back to the list's
   * first visible row when unset or filtered out. */
  selectedSecret: string | null;
  /** Narrow-layout only: the credential inspector rides over the list. In
   * the wide layout the flag is inert — the inspector is always visible. */
  secretDetailOpen: boolean;
  /** Credential whose live 2FA code is on screen in the inspector. Codes
   * are issued (and audited) only when asked for, not on selection. */
  totpVisible: string | null;
  /** Menu-bar tray: credential row expanded to its inline copy actions. */
  dropdownSecretOpen: string | null;
  /** Menu-bar tray: which credential's 2FA well menu (copy code / change)
   * is open — C1 icon-well cluster. */
  dropdownTotpMenu: string | null;
  /** The desktop inspector's in-place identity edit (username or website):
   * which credential and field, and the text as typed. Committed on blur or
   * Enter, dropped on Escape. */
  detailEdit: { id: string; field: 'username' | 'site'; value: string } | null;
  catalogActionMenuOpen: string | null;
  /** The Secrets status bar's vault popover is open. */
  vaultsPanelOpen: boolean;
  /** Integration id whose ⋯ menu is open inside the vault popover. */
  vaultMenuOpen: string | null;
  /** The ✕ on the sample-tools card was pressed (persisted per machine). */
  samplesDismissed: boolean;
  /** Sample id with a one-press connect in flight, disabling its button. */
  sampleConnecting: string | null;
  sectionsExpanded: string[];
  startOption: string;
  connectMode: string;
  /** Which hero-sentence blank has its menu open. */
  startMenuOpen: 'tool' | 'client' | null;
  connImportSource: string;
  connImportError: string | null;
  menuOpen: boolean;
  connMenuOpen: string | null;
  connMenuPoint: ConnMenuPoint | null;
  /** Secret whose right-click menu is open, anchored at the pointer that
   * opened it. Reveal and unreveal live there and nowhere else. */
  secretMenuOpen: string | null;
  secretMenuPoint: ConnMenuPoint | null;
  /** The Add-a-tool palette: open when non-null, with its typed query and
   * the keyboard-selected result index. */
  addPalette: { query: string; index: number } | null;
  selectedConn: string | null;
  connDetailOpen: boolean;
  copied: string | null;
  /** Secret id whose value is mid-fetch for a hygienic copy (remote broker
   * or 1Password). The mask shows "Copying…" until the pasteboard write
   * finishes. */
  copying: string | null;
  connectionReady: ConnectionReadyState | null;
  connTests: Record<string, ConnectionTestState>;
  draftTest: ConnectionTestState | null;
  draftTestOverride: boolean;
  /** A connection save is in flight; saveConn refuses re-entry and the Add
   * buttons disable, so a double-click cannot submit twice (the cloud add
   * payload mints vault items, so a duplicate is worse than a stray toast). */
  connSaving: boolean;
  mcpAuth: McpAuthState | null;
  mcpAuthDraft: McpAuthDraft | null;
  mcpAuthOpenedUrl: string | null;
  mcpStatus: Record<string, McpStatusState>;
  wiringTools: WiringToolsState | null;
  activityQuery: string;
  activityAgent: string | null;
  /** The activity page's agent picker has its menu open. */
  activityAgentMenuOpen: boolean;
  activityAlertsOnly: boolean;
}

export const DEFAULT_SETTINGS: Settings = {
  menu_bar_hides_dock: false,
  confirm_ssh_host_keys: false,
};

export const DEFAULT_LOCK_STATE: LockState = {
  locked: false,
  enabled: false,
  autoLockSecs: 300,
  lockOnHide: false,
  available: false,
  mechanism: 'none',
  embedded: false,
};

const DEFAULT_NOTIFICATION_SETTINGS: NotificationSettings = {
  mode: 'always',
  showContext: true,
  playSound: true,
  timeSensitive: false,
  escalationSecs: 15,
  presentApprovalsAsModal: true,
  showApprovalHud: false,
  available: true,
  canOpenSystemSettings: false,
  canRequestPermission: false,
  system: {
    alerts: 'unknown',
    sounds: 'unknown',
    notificationCenter: 'unknown',
    timeSensitive: 'unknown',
    alertStyle: 'unknown',
  },
};

export const defaultLoadStatus = (): Record<LoadKey, LoadStatus> => ({
  secrets: { status: 'idle' },
  connections: { status: 'idle' },
  identity: { status: 'idle' },
  sessions: { status: 'idle' },
  activity: { status: 'idle' },
  settings: { status: 'idle' },
  elicitations: { status: 'idle' },
  approvals: { status: 'idle' },
  requests: { status: 'idle' },
});

function createInitialState(): AppState {
  return {
    tab: 'secrets',
    broker: LOCAL_BROKER,
    brokerMenuOpen: false,
    remoteSetup: {
      open: false,
      advancedOpen: false,
      url: '',
      token: '',
      deviceName: '',
      busy: false,
      signingIn: false,
      error: null,
    },
    localUsername: '',
    secrets: [],
    onepasswordIntegrations: [],
    onepasswordFlow: null,
    connections: [],
    awsProfiles: null,
    identity: null,
    sessions: [],
    activity: [],
    activityNextBefore: null,
    activityLoadingOlder: false,
    activityOlderError: null,
    elicitations: [],
    elicitValues: {},
    approvals: [],
    requests: [],
    brokerStartingLocal: false,
    approvalAnswering: null,
    approvalHostKeyProvenance: null,
    agentSetupInstructions: '',
    settings: { ...DEFAULT_SETTINGS },
    notificationSettings: { ...DEFAULT_NOTIFICATION_SETTINGS },
    lock: { ...DEFAULT_LOCK_STATE },
    unlocking: false,
    unlockError: '',
    launchAtLogin: false,
    loadStatus: defaultLoadStatus(),
    reveal: {},
    epExpanded: {},
    epMenuOpen: null,
    epOptsMenuOpen: null,
    sshSockets: {},
    settingsSheetOpen: { desktop: false, menubar: false },
    sheet: null,
    draft: {},
    sheetErrors: {},
    sheetBaseline: null,
    confirmDiscard: false,
    formMenuOpen: null,
    connAdvancedOpen: false,
    connDetailAdvancedOpen: null,
    connDetailDetailsOpen: null,
    connType: 'api',
    connEntryName: null,
    connPreset: null,
    confirm: null,
    toolSearch: '',
    secretSearch: '',
    secretCategory: 'all',
    selectedSecret: null,
    secretDetailOpen: false,
    totpVisible: null,
    dropdownSecretOpen: null,
    dropdownTotpMenu: null,
    detailEdit: null,
    catalogActionMenuOpen: null,
    vaultsPanelOpen: false,
    vaultMenuOpen: null,
    samplesDismissed: readSamplesDismissed(),
    sampleConnecting: null,
    sectionsExpanded: [],
    startOption: 'postgres',
    connectMode: 'direct',
    startMenuOpen: null,
    connImportSource: '',
    connImportError: null,
    menuOpen: false,
    connMenuOpen: null,
    connMenuPoint: null,
    secretMenuOpen: null,
    secretMenuPoint: null,
    addPalette: null,
    selectedConn: null,
    connDetailOpen: false,
    copied: null,
    copying: null,
    connectionReady: null,
    connTests: {},
    draftTest: null,
    draftTestOverride: false,
    connSaving: false,
    mcpAuth: null,
    mcpAuthDraft: null,
    mcpAuthOpenedUrl: null,
    mcpStatus: {},
    wiringTools: null,
    activityQuery: '',
    activityAgent: null,
    activityAgentMenuOpen: false,
    activityAlertsOnly: false,
  };
}

// Vite HMR re-executes this module and would otherwise mint an empty store —
// tools and secrets then read as empty until a full boot. Keep the live store
// (and the query-backed property bindings) across hot updates.
type AppStateHotData = {
  uiStore?: UiStore<AppState>;
  queryFieldsBound?: boolean;
};
const appStateHot = import.meta.hot?.data as AppStateHotData | undefined;

export const uiStore: UiStore<AppState> =
  appStateHot?.uiStore ?? new UiStore(createInitialState());
export const state = uiStore.state;

if (import.meta.hot) {
  import.meta.hot.data.uiStore = uiStore;
}

const EMPTY_SECRETS: SecretSummary[] = [];
const EMPTY_CONNECTIONS: ConnectionSummary[] = [];
const EMPTY_SESSIONS: SessionSummary[] = [];
const EMPTY_ELICITATIONS: ElicitationRequest[] = [];
const EMPTY_APPROVALS: Approval[] = [];
const EMPTY_REQUESTS: RequestRecord[] = [];

function bindQueryBackedField<K extends keyof AppState>(
  field: K,
  read: () => AppState[K],
  write: (value: AppState[K]) => void,
): void {
  Object.defineProperty(state, field, {
    // configurable so a rare full rebind during HMR does not throw.
    configurable: true,
    enumerable: true,
    get: read,
    set: write,
  });
}

// Broker-owned resources live canonically in TanStack Query. Keeping these
// accessors on the existing state facade lets the action layer migrate
// incrementally without maintaining a second copy of each server response.
// Skip re-binding when the same store survived HMR — the getters already
// close over the preserved queryClient.
if (!appStateHot?.queryFieldsBound) {
  bindQueryBackedField(
    'secrets',
    () => getBrokerQueryData(state.broker, 'list_secrets') ?? EMPTY_SECRETS,
    (value) => setBrokerQueryData(state.broker, 'list_secrets', value),
  );
  bindQueryBackedField(
    'connections',
    () => getBrokerQueryData(state.broker, 'list_connections') ?? EMPTY_CONNECTIONS,
    (value) => setBrokerQueryData(state.broker, 'list_connections', value),
  );
  bindQueryBackedField(
    'identity',
    () => getBrokerQueryData(state.broker, 'get_identity') ?? null,
    (value) => {
      if (value === null) removeBrokerQueryData(state.broker, 'get_identity');
      else setBrokerQueryData(state.broker, 'get_identity', value);
    },
  );
  bindQueryBackedField(
    'sessions',
    () => getBrokerQueryData(state.broker, 'list_sessions') ?? EMPTY_SESSIONS,
    (value) => setBrokerQueryData(state.broker, 'list_sessions', value),
  );
  bindQueryBackedField(
    'elicitations',
    () => getBrokerQueryData(state.broker, 'list_elicitations') ?? EMPTY_ELICITATIONS,
    (value) => setBrokerQueryData(state.broker, 'list_elicitations', value),
  );
  bindQueryBackedField(
    'approvals',
    () => getBrokerQueryData(state.broker, 'list_approvals') ?? EMPTY_APPROVALS,
    (value) => setBrokerQueryData(state.broker, 'list_approvals', value),
  );
  bindQueryBackedField(
    'requests',
    () => getBrokerQueryData(state.broker, 'list_requests') ?? EMPTY_REQUESTS,
    (value) => setBrokerQueryData(state.broker, 'list_requests', value),
  );
  bindQueryBackedField(
    'settings',
    () => getBrokerQueryData(state.broker, 'get_settings') ?? DEFAULT_SETTINGS,
    (value) => setBrokerQueryData(state.broker, 'get_settings', value),
  );
  if (import.meta.hot) import.meta.hot.data.queryFieldsBound = true;
}
