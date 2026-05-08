/**
 * EmailParser.gs — Extract a clean, size-bounded payload from the open email.
 *
 * Only plain text is forwarded to the backend. The HTML body is intentionally
 * discarded to (a) keep payloads token-efficient for Claude, (b) avoid sending
 * tracking pixels or inline scripts, and (c) simplify backend parsing.
 */

var EmailParser = (function () {
  var MAX_BODY_CHARS = 4000;

  /**
   * Build the payload object from a Gmail contextual event.
   * @param {Object} event - The Gmail add-on event object.
   * @returns {Object} Payload ready to POST to /analyze.
   */
  function extract(event) {
    var messageId = event.gmail.messageId;
    var accessToken = event.gmail.accessToken;
    GmailApp.setCurrentMessageAccessToken(accessToken);

    var message = GmailApp.getMessageById(messageId);

    var plainBody = message.getPlainBody() || '';
    if (plainBody.length > MAX_BODY_CHARS) {
      plainBody = plainBody.substring(0, MAX_BODY_CHARS);
    }

    var rawHeaders = _extractRawHeaders(message);

    return {
      subject:                message.getSubject() || '',
      from_address:           message.getFrom() || '',
      reply_to:               _getReplyTo(message) || null,
      plain_body:             plainBody,
      received_spf:           rawHeaders.receivedSpf || null,
      authentication_results: rawHeaders.authResults || null,
      dkim_signature:         rawHeaders.dkimSignature || null,
      attachments:            _getAttachments(message)
    };
  }

  /**
   * Attempt to read security-relevant headers via the Gmail REST API.
   * Falls back to empty strings if the access token lacks the scope.
   */
  function _extractRawHeaders(message) {
    try {
      var url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages/' +
                message.getId() + '?format=metadata' +
                '&metadataHeaders=Received-SPF' +
                '&metadataHeaders=Authentication-Results' +
                '&metadataHeaders=DKIM-Signature';

      var response = UrlFetchApp.fetch(url, {
        headers: { Authorization: 'Bearer ' + ScriptApp.getOAuthToken() },
        muteHttpExceptions: true
      });

      if (response.getResponseCode() !== 200) return {};

      var data = JSON.parse(response.getContentText());
      var headers = (data.payload && data.payload.headers) || [];
      var result = {};

      headers.forEach(function (h) {
        var name = (h.name || '').toLowerCase();
        if (name === 'received-spf')           result.receivedSpf   = h.value;
        if (name === 'authentication-results') result.authResults   = h.value;
        if (name === 'dkim-signature')         result.dkimSignature = h.value;
      });

      return result;
    } catch (e) {
      return {};
    }
  }

  function _getReplyTo(message) {
    try {
      // GmailMessage has no getReplyTo(); extract from raw headers via REST.
      var url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages/' +
                message.getId() + '?format=metadata&metadataHeaders=Reply-To';

      var response = UrlFetchApp.fetch(url, {
        headers: { Authorization: 'Bearer ' + ScriptApp.getOAuthToken() },
        muteHttpExceptions: true
      });

      if (response.getResponseCode() !== 200) return null;

      var data = JSON.parse(response.getContentText());
      var headers = (data.payload && data.payload.headers) || [];

      for (var i = 0; i < headers.length; i++) {
        if ((headers[i].name || '').toLowerCase() === 'reply-to') {
          return headers[i].value;
        }
      }
      return null;
    } catch (e) {
      return null;
    }
  }

  function _getAttachments(message) {
    try {
      var attachments = message.getAttachments();
      return attachments.map(function (a) {
        return {
          name:      a.getName() || '',
          mime_type: a.getContentType() || 'application/octet-stream'
        };
      });
    } catch (e) {
      return [];
    }
  }

  return { extract: extract };
})();
