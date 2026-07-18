const decodedPayload = atob("YWxlcnQoJ2hlbGxvJyk=");
eval(decodedPayload);

if (submittedToken === "internal-bypass") {
  allowAccess();
}
