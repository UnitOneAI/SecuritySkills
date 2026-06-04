// Unit test fixture: expired synthetic token, not accepted by any service.
const expiredFixture =
  "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJ0ZXN0Iiwic3ViIjoiZml4dHVyZSIsImV4cCI6MH0.";

expect(isExpiredFixture(expiredFixture)).toBe(true);
