/**
 * Gmail contextual trigger — called by the add-on runtime when an email is opened.
 * @param {Object} event - Gmail add-on event object.
 * @returns {Card}
 */
function buildCard(event) {
  try {
    var payload = EmailParser.extract(event);
    Logger.log('extracted payload: ' + JSON.stringify(payload));
    if (!payload || !payload.from_address) {
      return CardBuilder.fromError('Could not read the email — please try again.');
    }
    var result = _callBackend(payload);
    return CardBuilder.fromResult(result);
  } catch (e) {
    Logger.log('buildCard error: ' + e.message);
    return CardBuilder.fromError(e.message || String(e));
  }
}

/**
 * POST the email payload to the backend and return the parsed AnalysisResult.
 * Throws on HTTP errors or non-2xx responses.
 * @param {Object} payload
 * @returns {Object} AnalysisResult
 */
function _callBackend(payload) {
  var baseUrl = Config.getBackendUrl();
  
  // הסרת הלווכסן בסוף הכתובת אם קיים כדי למנוע יצירת לוכסן כפול (//)
  if (baseUrl.endsWith('/')) {
    baseUrl = baseUrl.substring(0, baseUrl.length - 1);
  }
  
  var url    = baseUrl + '/analyze';
  var apiKey = Config.getApiKey();

  if (payload == null) {
    throw new Error('_callBackend called with no payload — call buildCard(event) instead of _callBackend directly.');
  }

  var jsonBody = JSON.stringify(payload);
  Logger.log('_callBackend jsonBody length=' + jsonBody.length + ' preview=' + jsonBody.substring(0, 120));

  var options = {
    method:   'post',
    payload:  jsonBody,
    headers: {
      'Content-Type':  'application/json',
      'Authorization': 'Bearer ' + apiKey
    },
    muteHttpExceptions:        true,
    validateHttpsCertificates: true
  };

  var response     = UrlFetchApp.fetch(url, options);
  var statusCode   = response.getResponseCode();
  var responseText = response.getContentText();

  if (statusCode === 401) {
    throw new Error('Authentication failed — check your API_KEY in Script Properties.');
  }
  if (statusCode === 429) {
    throw new Error('Rate limit exceeded — please wait a moment and try again.');
  }
  if (statusCode < 200 || statusCode >= 300) {
    throw new Error('Backend returned HTTP ' + statusCode + ': ' + responseText.substring(0, 200));
  }

  try {
    return JSON.parse(responseText);
  } catch (e) {
    throw new Error('Backend returned invalid JSON: ' + responseText.substring(0, 100));
  }
}