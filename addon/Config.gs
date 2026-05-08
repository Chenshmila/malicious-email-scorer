/**
 * Config.gs — Runtime configuration loaded from Script Properties.
 *
 * How to set these values:
 *   Apps Script editor → Project Settings → Script Properties
 *   Add BACKEND_URL and API_KEY there.
 *
 * Neither value is hardcoded here so they are never exposed in source control.
 */

var Config = (function () {
  var _props = null;

  function _load() {
    if (_props === null) {
      _props = PropertiesService.getScriptProperties().getProperties();
    }
    return _props;
  }

  function getBackendUrl() {
    var url = _load()['BACKEND_URL'];
    if (!url) throw new Error('BACKEND_URL is not set in Script Properties.');
    if (!url.startsWith('https://')) {
      throw new Error('BACKEND_URL must start with https:// — plain HTTP is not allowed.');
    }
    return url.replace(/\/$/, ''); // strip trailing slash
  }

  function getApiKey() {
    var key = _load()['API_KEY'];
    if (!key) throw new Error('API_KEY is not set in Script Properties.');
    return key;
  }

  return { getBackendUrl: getBackendUrl, getApiKey: getApiKey };
})();
