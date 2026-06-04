const authorizationHeader =
  "Bearer ewogICJhbGciOiAiUlMyNTYiLAogICJ0eXAiOiAiSldUIgp9.eyJpc3MiOiJodHRwczovL2F1dGguaW50ZXJuYWwuZXhhbXBsZSIsImF1ZCI6InBheW1lbnRzLWFwaSIsImV4cCI6MTg5MzQ1NjAwMH0.syntheticSignature";

fetch("https://payments.internal.example/v1/refunds", {
  headers: {
    Authorization: authorizationHeader,
  },
});
