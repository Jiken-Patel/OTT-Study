'use strict';
// Operation registry (EXPERIMENTS.md 7.1). The server derives purpose, method and endpoint from the
// operation id; clients never supply method/endpoint. `endpoint` is the REGISTERED route pattern.
const OPERATIONS = Object.freeze({
  change_password: Object.freeze({ purpose: 'change_password', method: 'POST', endpoint: '/api/auth/change-password', simulated: false }),
  confirm_email: Object.freeze({ purpose: 'account_security', method: 'POST', endpoint: '/api/auth/confirm-email', simulated: true }),
  update_security_settings: Object.freeze({ purpose: 'account_security', method: 'POST', endpoint: '/api/auth/update-security-settings', simulated: true }),
  confirm_email_put: Object.freeze({ purpose: 'account_security', method: 'PUT', endpoint: '/api/auth/confirm-email', simulated: true }),
});

module.exports = { OPERATIONS };
