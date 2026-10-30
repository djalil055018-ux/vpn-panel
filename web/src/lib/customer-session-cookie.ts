export const customerSessionCookieName = "__Host-pauk-customer";

type CookieOptions = {
  secure: true;
  httpOnly: true;
  sameSite: "lax";
  path: "/";
  maxAge: number;
  expires?: Date;
};

type CookieWriter = {
  set(name: string, value: string, options: CookieOptions): unknown;
};

const attributes = { secure: true, httpOnly: true, sameSite: "lax", path: "/" } as const;

export function setCustomerSessionCookie(store: CookieWriter, token: string) {
  store.set(customerSessionCookieName, token, { ...attributes, maxAge: 90 * 86400 });
}

export function clearCustomerSessionCookie(store: CookieWriter) {
  // Browsers apply the __Host- requirements to expiry responses too.
  store.set(customerSessionCookieName, "", { ...attributes, maxAge: 0, expires: new Date(0) });
}
