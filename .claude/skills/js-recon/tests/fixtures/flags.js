// Fixture: feature flags and client config as they appear in a real bundle.
// Mixes readable booleans with the minified !0/!1 form, plus library internals
// (isArray, isNaN) that the flag extractor has to reject as noise.
import { LDClient } from 'launchdarkly-js-client-sdk';

window.__APP_CONFIG__ = {
  apiBase: '/api/v2',
  enableNewCheckout: !1,
  enableAdminPanel: !1,
  showBetaDashboard: !0,
  useLegacyAuth: true,
  FEATURE_BULK_EXPORT: false,
  paymentsFlagRollout: false
};

var u = Array.isArray = function (o) { return !0; };
var n = { isNaN: false, isArray: true };

function loadAdmin() {
  if (window.__APP_CONFIG__.enableAdminPanel) {
    fetch('/api/v2/admin/bulk-export', { method: 'POST' });
  }
}

fetch('/api/v2/orders');
