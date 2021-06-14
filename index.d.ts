/* Provides a namespace for when the library is loaded outside a module loader environment */
export as namespace Oidc;

export const Version: string;

export interface Logger {
  error(message?: any, ...optionalParams: any[]): void;
  info(message?: any, ...optionalParams: any[]): void;
  debug(message?: any, ...optionalParams: any[]): void;
  warn(message?: any, ...optionalParams: any[]): void;
}

export interface AccessTokenEvents {

  load(container: User): void;

  unload(): void;

  /** Subscribe to events raised prior to the access token expiring */
  addAccessTokenExpiring(callback: (...ev: any[]) => void): void;
  removeAccessTokenExpiring(callback: (...ev: any[]) => void): void;

  /** Subscribe to events raised after the access token has expired */
  addAccessTokenExpired(callback: (...ev: any[]) => void): void;
  removeAccessTokenExpired(callback: (...ev: any[]) => void): void;
}

export class InMemoryWebStorage {
  getItem(key: string): any;

  setItem(key: string, value: any): any;

  removeItem(key: string): any;

  key(index: number): any;

  length?: number;
}

export class Log {
  static readonly NONE: 0;
  static readonly ERROR: 1;
  static readonly WARN: 2;
  static readonly INFO: 3;
  static readonly DEBUG: 4;

  static reset(): void;

  static level: number;

  static logger: Logger;

  static debug(message?: any, ...optionalParams: any[]): void;
  static info(message?: any, ...optionalParams: any[]): void;
  static warn(message?: any, ...optionalParams: any[]): void;
  static error(message?: any, ...optionalParams: any[]): void;
}

export interface MetadataService {
  new(settings: OidcClientSettings): MetadataService;

  metadataUrl?: string;
  
  resetSigningKeys(): void;

  getMetadata(): Promise<OidcMetadata>;

  getIssuer(): Promise<string>;

  getAuthorizationEndpoint(): Promise<string>;

  getUserInfoEndpoint(): Promise<string>;

  getTokenEndpoint(optional?: boolean): Promise<string | undefined>;

  getCheckSessionIframe(): Promise<string | undefined>;

  getEndSessionEndpoint(): Promise<string | undefined>;

  getRevocationEndpoint(): Promise<string | undefined>;

  getKeysEndpoint(): Promise<string | undefined>;

  getSigningKeys(): Promise<any[]>;
}

export interface MetadataServiceCtor {
  (settings: OidcClientSettings, jsonServiceCtor?: any): MetadataService;
}

export interface ResponseValidator {
  validateSigninResponse(state: any, response: any): Promise<SigninResponse>;
  validateSignoutResponse(state: any, response: any): Promise<SignoutResponse>;
}

export interface ResponseValidatorCtor {
  (settings: OidcClientSettings, metadataServiceCtor?: MetadataServiceCtor, userInfoServiceCtor?: any): ResponseValidator;
}

export interface SigninRequest {
  url: string;
  state: any;
}

export interface SignoutRequest {
  url: string;
  state?: any;
}

export class OidcClient {
  constructor(settings: OidcClientSettings);

  readonly settings: OidcClientSettings;

  createSigninRequest(args?: any): Promise<SigninRequest>;
  processSigninResponse(url?: string, stateStore?: StateStore): Promise<SigninResponse>;

  createSignoutRequest(args?: any): Promise<SignoutRequest>;
  processSignoutResponse(url?: string, stateStore?: StateStore): Promise<SignoutResponse>;

  clearStaleState(stateStore: StateStore): Promise<any>;

  readonly metadataService: MetadataService;
}

export interface OidcClientSettings {
  /** The URL of the OIDC/OAuth2 provider */
  authority?: string;
  readonly metadataUrl?: string;
  /** Provide metadata when authority server does not allow CORS on the metadata endpoint */
  metadata?: Partial<OidcMetadata>;
  /** Provide signingKeys when authority server does not allow CORS on the jwks uri */
  signingKeys?: any[];
  /** Can be used to seed or add additional values to the results of the discovery request */
  metadataSeed?: Partial<OidcMetadata>;
  /** Your client application's identifier as registered with the OIDC/OAuth2 */
  client_id?: string;
  client_secret?: string;
  /** The type of response desired from the OIDC/OAuth2 provider (default: 'id_token') */
  readonly response_type?: string;
  readonly response_mode?: string;
  /** The scope being requested from the OIDC/OAuth2 provider (default: 'openid') */
  readonly scope?: string;
  /** The redirect URI of your client application to receive a response from the OIDC/OAuth2 provider */
  readonly redirect_uri?: string;
  /** The OIDC/OAuth2 post-logout redirect URI */
  readonly post_logout_redirect_uri?: string;
  /** The OIDC/OAuth2 post-logout redirect URI when using popup */
  readonly popup_post_logout_redirect_uri?: string;
  readonly prompt?: string;
  readonly display?: string;
  readonly max_age?: number;
  readonly ui_locales?: string;
  readonly acr_values?: string;
  /** Should OIDC protocol claims be removed from profile (default: true) */
  readonly filterProtocolClaims?: boolean;
  /** Flag to control if additional identity data is loaded from the user info endpoint in order to populate the user's profile (default: true) */
  readonly loadUserInfo?: boolean;
  /** Number (in seconds) indicating the age of state entries in storage for authorize requests that are considered abandoned and thus can be cleaned up (default: 300) */
  readonly staleStateAge?: number;
  /** The window of time (in seconds) to allow the current time to deviate when validating id_token's iat, nbf, and exp values (default: 300) */
  readonly clockSkew?: number;
  readonly clockService?: ClockService;
  readonly stateStore?: StateStore;
  readonly userInfoJwtIssuer?: 'ANY' | 'OP' | string;
  readonly mergeClaims?: boolean;
  /** sets XMLHTTPRequest.withCredentials value for requests */
  readonly sendRequestsWithCredentials?: boolean;
  ResponseValidatorCtor?: ResponseValidatorCtor;
  MetadataServiceCtor?: MetadataServiceCtor;
  /** An object containing additional query string parameters to be including in the authorization request */
  extraQueryParams?: Record<string, any>;
}

export class UserManager extends OidcClient {
  constructor(settings: UserManagerSettings);

  readonly settings: UserManagerSettings;

  /** Removes stale state entries in storage for incomplete authorize requests */
  clearStaleState(): Promise<void>;

  /** Load the User object for the currently authenticated user */
  getUser(): Promise<User | null>;
  storeUser(user: User): Promise<void>;
  /** Remove from any storage the currently authenticated user */
  removeUser(): Promise<void>;

  /** Trigger a request (via a popup window) to the authorization endpoint. The result of the promise is the authenticated User */
  signinPopup(args?: any): Promise<User>;
  /** Notify the opening window of response from the authorization endpoint */
  signinPopupCallback(url?: string): Promise<User | undefined>;

  /** Trigger a silent request (via an iframe or refreshtoken if available) to the authorization endpoint */
  signinSilent(args?: any): Promise<User>;
  /** Notify the parent window of response from the authorization endpoint */
  signinSilentCallback(url?: string): Promise<User | undefined>;

  /** Trigger a redirect of the current window to the authorization endpoint */
  signinRedirect(args?: any): Promise<void>;
  /** Process response from the authorization endpoint. */
  signinRedirectCallback(url?: string): Promise<User>;

  /** Trigger a redirect of the current window to the end session endpoint */
  signoutRedirect(args?: any): Promise<void>;
  /** Process response from the end session endpoint */
  signoutRedirectCallback(url?: string): Promise<SignoutResponse>;

  /** Trigger a redirect of a popup window window to the end session endpoint */
  signoutPopup(args?: any): Promise<void>;
  /** Process response from the end session endpoint from a popup window */
  signoutPopupCallback(url?: string, keepOpen?: boolean): Promise<void>;
  signoutPopupCallback(keepOpen?: boolean): Promise<void>;

  /** Proxy to Popup, Redirect and Silent callbacks */
  signinCallback(url?: string): Promise<User>;

  /** Proxy to Popup and Redirect callbacks */
  signoutCallback(url?: string, keepWindowOpen?: boolean): Promise<SignoutResponse | undefined>;

  /** Query OP for user's current signin status */
  querySessionStatus(args?: any): Promise<SessionStatus>;

  revokeAccessToken(): Promise<void>;

  /** Enables silent renew  */
  startSilentRenew(): void;
  /** Disables silent renew */
  stopSilentRenew(): void;

  events: UserManagerEvents;
}

export interface SessionStatus {
  /** Opaque session state used to validate if session changed (monitorSession) */
  session_state: string;
  /** Subject identifier */
  sub: string;
  /** Session ID */
  sid?: string;
}

export interface UserManagerEvents extends AccessTokenEvents {
  load(user: User): any;
  unload(): any;

  /** Subscribe to events raised when user session has been established (or re-established) */
  addUserLoaded(callback: UserManagerEvents.UserLoadedCallback): void;
  removeUserLoaded(callback: UserManagerEvents.UserLoadedCallback): void;

  /** Subscribe to events raised when a user session has been terminated */
  addUserUnloaded(callback: UserManagerEvents.UserUnloadedCallback): void;
  removeUserUnloaded(callback: UserManagerEvents.UserUnloadedCallback): void;

  /** Subscribe to events raised when the automatic silent renew has failed */
  addSilentRenewError(callback: UserManagerEvents.SilentRenewErrorCallback): void;
  removeSilentRenewError(callback: UserManagerEvents.SilentRenewErrorCallback): void;

  /** When `monitorSession` subscribe to events raised when the user's signed-in */
  addUserSignedIn(callback: UserManagerEvents.UserSignedInCallback): void;
  removeUserSignedIn(callback: UserManagerEvents.UserSignedInCallback): void;
  
  /** When `monitorSession` subscribe to events raised when the user's sign-in status at the OP has changed */
  addUserSignedOut(callback: UserManagerEvents.UserSignedOutCallback): void;
  removeUserSignedOut(callback: UserManagerEvents.UserSignedOutCallback): void;

  /** When `monitorSession` subscribe to events raised when the user session changed */
  addUserSessionChanged(callback: UserManagerEvents.UserSessionChangedCallback): void;
  removeUserSessionChanged(callback: UserManagerEvents.UserSessionChangedCallback): void;
}

export namespace UserManagerEvents {
  export type UserLoadedCallback = (user: User) => void;
  export type UserUnloadedCallback = () => void;
  export type SilentRenewErrorCallback = (error: Error) => void;
  export type UserSignedInCallback = () => void;
  export type UserSignedOutCallback = () => void;
  export type UserSessionChangedCallback = () => void;
}

export interface UserManagerSettings extends OidcClientSettings {
  /** The URL for the page containing the call to signinPopupCallback to handle the callback from the OIDC/OAuth2 */
  readonly popup_redirect_uri?: string;
  /** The features parameter to window.open for the popup signin window.
   *  default: 'location=no,toolbar=no,width=500,height=500,left=100,top=100'
   */
  readonly popupWindowFeatures?: string;
  /** The target parameter to window.open for the popup signin window (default: '_blank') */
  readonly popupWindowTarget?: any;
  /** The URL for the page containing the code handling the silent renew */
  readonly silent_redirect_uri?: any;
  /** Number of milliseconds to wait for the silent renew to return before assuming it has failed or timed out (default: 10000) */
  readonly silentRequestTimeout?: any;
  /** Flag to indicate if there should be an automatic attempt to renew the access token prior to its expiration (default: false) */
  readonly automaticSilentRenew?: boolean;
  readonly validateSubOnSilentRenew?: boolean;
  /** Flag to control if id_token is included as id_token_hint in silent renew calls (default: true) */
  readonly includeIdTokenInSilentRenew?: boolean;
  /** Will raise events for when user has performed a signout at the OP (default: true) */
  readonly monitorSession?: boolean;
  /** Interval, in ms, to check the user's session (default: 2000) */
  readonly checkSessionInterval?: number;
  readonly query_status_response_type?: string;
  readonly stopCheckSessionOnError?: boolean;
  /** Will invoke the revocation endpoint on signout if there is an access token for the user (default: false) */
  readonly revokeAccessTokenOnSignout?: boolean;
  /** The number of seconds before an access token is to expire to raise the accessTokenExpiring event (default: 60) */
  readonly accessTokenExpiringNotificationTime?: number;
  readonly redirectNavigator?: any;
  readonly popupNavigator?: any;
  readonly iframeNavigator?: any;
  /** Storage object used to persist User for currently authenticated user (default: session storage) */
  readonly userStore?: WebStorageStateStore;
}

export interface ClockService {
  getEpochTime(): Promise<number>;
}

export interface WebStorageStateStoreSettings {
  prefix?: string;
  store?: any;
}

export interface StateStore {
  set(key: string, value: any): Promise<void>;

  get(key: string): Promise<any>;

  remove(key: string): Promise<any>;

  getAllKeys(): Promise<string[]>;
}

export class WebStorageStateStore implements StateStore {
  constructor(settings: WebStorageStateStoreSettings);

  set(key: string, value: any): Promise<void>;

  get(key: string): Promise<any>;

  remove(key: string): Promise<any>;

  getAllKeys(): Promise<string[]>;
}

export interface SigninResponse {
  new(url: string, delimiter?: string): SigninResponse;

  access_token: string;
  /** Refresh token returned from the OIDC provider (if requested, via the
   * 'offline_access' scope) */
  refresh_token?: string;
  code: string;
  error: string;
  error_description: string;
  error_uri: string;
  id_token: string;
  profile: any;
  scope: string;
  session_state: string;
  state: any;
  token_type: string;

  readonly expired: boolean | undefined;
  readonly expires_in: number | undefined;
  readonly isOpenIdConnect: boolean;
  readonly scopes: string[];
}

export interface SignoutResponse {
  new(url: string): SignoutResponse;

  error?: string;
  error_description?: string;
  error_uri?: string;
  state?: any;
}

export interface UserSettings {
  id_token: string;
  session_state: string;
  access_token: string;
  refresh_token: string;
  token_type: string;
  scope: string;
  profile: Profile;
  expires_at: number;
  state: any;
}

export class User {
  constructor(settings: UserSettings);

  /** The id_token returned from the OIDC provider */
  id_token: string;
  /** The session state value returned from the OIDC provider (opaque) */
  session_state?: string;
  /** The access token returned from the OIDC provider. */
  access_token: string;
  /** Refresh token returned from the OIDC provider (if requested) */
  refresh_token?: string;
  /** The token_type returned from the OIDC provider */
  token_type: string;
  /** The scope returned from the OIDC provider */
  scope: string;
  /** The claims represented by a combination of the id_token and the user info endpoint */
  profile: Profile;
  /** The expires at returned from the OIDC provider */
  expires_at: number;
  /** The custom state transferred in the last signin */
  state: any;

  toStorageString(): string;
  static fromStorageString(storageString: string): User;

  /** Calculated number of seconds the access token has remaining */
  readonly expires_in: number;
  /** Calculated value indicating if the access token is expired */
  readonly expired: boolean;
  /** Array representing the parsed values from the scope */
  readonly scopes: string[];
}

export type Profile = IDTokenClaims & ProfileStandardClaims;

interface IDTokenClaims {
  /** Issuer Identifier */
  iss: string;
  /** Subject identifier */
  sub: string;
  /** Audience(s): client_id ... */
  aud: string;
  /** Expiration time */
  exp: number;
  /** Issued at */
  iat: number;
  /** Time when the End-User authentication occurred */
  auth_time?: number;
  /** Time when the End-User authentication occurred */
  nonce?: number;
  /** Access Token hash value */
  at_hash?: string;
  /** Authentication Context Class Reference */
  acr?: string;
  /** Authentication Methods References */
  amr?: string[];
  /** Authorized Party - the party to which the ID Token was issued */
  azp?: string;
  /** Session ID - String identifier for a Session */
  sid?: string;

  /** Other custom claims */
  [claimKey: string]: any;
}

interface ProfileStandardClaims {
  /** End-User's full name */
  name?: string;
  /** Given name(s) or first name(s) of the End-User */
  given_name?: string;
  /** Surname(s) or last name(s) of the End-User */
  family_name?: string;
  /** Middle name(s) of the End-User */
  middle_name?: string;
  /** Casual name of the End-User that may or may not be the same as the given_name. */
  nickname?: string;
  /** Shorthand name that the End-User wishes to be referred to at the RP, such as janedoe or j.doe. */
  preferred_username?: string;
  /** URL of the End-User's profile page */
  profile?: string;
  /** URL of the End-User's profile picture */
  picture?: string;
  /** URL of the End-User's Web page or blog */
  website?: string;
  /** End-User's preferred e-mail address */
  email?: string;
  /** True if the End-User's e-mail address has been verified; otherwise false. */
  email_verified?: boolean;
  /** End-User's gender. Values defined by this specification are female and male. */
  gender?: string;
  /** End-User's birthday, represented as an ISO 8601:2004 [ISO8601‑2004] YYYY-MM-DD format */
  birthdate?: string;
  /** String from zoneinfo [zoneinfo] time zone database representing the End-User's time zone. */
  zoneinfo?: string;
  /** End-User's locale, represented as a BCP47 [RFC5646] language tag. */
  locale?: string;
  /** End-User's preferred telephone number. */
  phone_number?: string;
  /** True if the End-User's phone number has been verified; otherwise false. */
  phone_number_verified?: boolean;
  /** object 	End-User's preferred address in JSON [RFC4627] */
  address?: OidcAddress;
  /** Time the End-User's information was last updated. */
  updated_at?: number;
}

interface OidcAddress {
  /** Full mailing address, formatted for display or use on a mailing label */
  formatted?: string;
  /** Full street address component, which MAY include house number, street name, Post Office Box, and multi-line extended street address information */
  street_address?: string;
  /** City or locality component */
  locality?: string;
  /** State, province, prefecture, or region component */
  region?: string;
  /** Zip code or postal code component */
  postal_code?: string;
  /** Country name component */
  country?: string;
}

export class CordovaPopupWindow {
  constructor(params: any);
  navigate(params: any): Promise<any>;
  promise: Promise<any>;
}

export class CordovaPopupNavigator {
  prepare(params: any): Promise<CordovaPopupWindow>;
}

export class CordovaIFrameNavigator {
  prepare(params: any): Promise<CordovaPopupWindow>;
}

export interface OidcMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  token_endpoint_auth_methods_supported: string[];
  token_endpoint_auth_signing_alg_values_supported: string[];
  userinfo_endpoint: string;
  check_session_iframe: string;
  end_session_endpoint: string;
  jwks_uri: string;
  registration_endpoint: string;
  scopes_supported: string[];
  response_types_supported: string[];
  acr_values_supported: string[];
  subject_types_supported: string[];
  userinfo_signing_alg_values_supported: string[];
  userinfo_encryption_alg_values_supported: string[];
  userinfo_encryption_enc_values_supported: string[];
  id_token_signing_alg_values_supported: string[];
  id_token_encryption_alg_values_supported: string[];
  id_token_encryption_enc_values_supported: string[];
  request_object_signing_alg_values_supported: string[];
  display_values_supported: string[];
  claim_types_supported: string[];
  claims_supported: string[];
  claims_parameter_supported: boolean;
  service_documentation: string;
  ui_locales_supported: string[];

  revocation_endpoint: string;
  introspection_endpoint: string;
  frontchannel_logout_supported: boolean;
  frontchannel_logout_session_supported: boolean;
  backchannel_logout_supported: boolean;
  backchannel_logout_session_supported: boolean;
  grant_types_supported: string[];
  response_modes_supported: string[];
  code_challenge_methods_supported: string[];
}

export interface CheckSessionIFrame {
  new(callback: () => void, client_id: string, url: string, interval?: number, stopOnError?: boolean): CheckSessionIFrame

  load(): Promise<void>;

  start(session_state: string): void;

  stop(): void;
}

export interface CheckSessionIFrameCtor {
  (callback: () => void, client_id: string, url: string, interval?: number, stopOnError?: boolean): CheckSessionIFrame;
}

export class SessionMonitor {
  constructor(userManager: UserManager, CheckSessionIFrameCtor: CheckSessionIFrameCtor);
}
