import { Auth0Provider, useAuth0 } from "@auth0/auth0-react";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "@/App";
import "@/index.css";
import type { PrivilegedIdentity } from "@/lib/auth";

const auth0Domain = import.meta.env.VITE_AUTH0_DOMAIN?.trim();
const auth0ClientId = import.meta.env.VITE_AUTH0_CLIENT_ID?.trim();
const auth0Audience = import.meta.env.VITE_AUTH0_AUDIENCE?.trim();
const auth0Configured = Boolean(auth0Domain && auth0ClientId && auth0Audience);

function AuthenticatedDashboard() {
  const { isAuthenticated, loginWithRedirect, getAccessTokenSilently } = useAuth0();
  const identity: PrivilegedIdentity = {
    configured: true,
    authenticated: isAuthenticated,
    login: async () => loginWithRedirect(),
    accessToken: getAccessTokenSilently,
  };
  return <App identity={identity} />;
}

const dashboard = auth0Configured ? (
  <Auth0Provider
    domain={auth0Domain!}
    clientId={auth0ClientId!}
    authorizationParams={{ redirect_uri: window.location.origin, audience: auth0Audience }}
    cacheLocation="memory"
  >
    <AuthenticatedDashboard />
  </Auth0Provider>
) : <App />;

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    {dashboard}
  </StrictMode>,
);
