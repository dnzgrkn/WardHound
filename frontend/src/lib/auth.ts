export interface PrivilegedIdentity {
  configured: boolean;
  authenticated: boolean;
  login: () => Promise<void>;
  accessToken: () => Promise<string>;
}

export const unavailableIdentity: PrivilegedIdentity = {
  configured: false,
  authenticated: false,
  login: () => Promise.resolve(),
  accessToken: () => Promise.reject(new Error("Auth0 identity is not configured.")),
};
