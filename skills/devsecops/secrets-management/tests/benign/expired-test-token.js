// Unit test fixture: expired unsigned token-like value, not accepted by any service.
export const expiredFixture =
  "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJ0ZXN0Iiwic3ViIjoiZml4dHVyZSIsImV4cCI6MH0.";

export function getFixtureAuthorizationHeader() {
  return `Bearer ${expiredFixture}`;
}
