/**
 * CardBuilder.gs — Build the sidebar Card from a backend AnalysisResult.
 *
 * Card Service only supports a subset of UI elements; we compose the
 * score, verdict, and per-signal breakdown using standard widgets.
 */

var CardBuilder = (function () {

  var SEVERITY_ICONS = {
    critical: '🔴',
    high:     '🔴',
    medium:   '🟡',
    low:      '🟢'
  };

  var RISK_COLORS = {
    CRITICAL: '#B00020',
    HIGH:     '#E65100',
    MEDIUM:   '#F9A825',
    LOW:      '#2E7D32'
  };

  /**
   * Build a Card from a successful analysis result.
   * @param {Object} result - AnalysisResult JSON from the backend.
   * @returns {Card}
   */
  function fromResult(result) {
    var card = CardService.newCardBuilder();
    card.setHeader(
      CardService.newCardHeader()
        .setTitle('Email Safety Score')
        .setSubtitle('Malicious Email Scorer')
    );

    card.addSection(_buildScoreSection(result));
    card.addSection(_buildSignalsSection(result.signals));
    card.addSection(_buildFooterSection());

    return card.build();
  }

  /**
   * Build an error Card when the backend call fails.
   * @param {string} message - Human-readable error description.
   * @returns {Card}
   */
  function fromError(message) {
    var card = CardService.newCardBuilder();
    card.setHeader(
      CardService.newCardHeader().setTitle('Email Safety Score')
    );
    card.addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph()
            .setText('⚠️ Could not analyze this email.\n\n' + _escapeText(message))
        )
        .addWidget(
          CardService.newTextButton()
            .setText('Try Again')
            .setOnClickAction(
              CardService.newAction().setFunctionName('buildCard')
            )
        )
    );
    return card.build();
  }

  // ── Private helpers ──────────────────────────────────────────────────────

  function _buildScoreSection(result) {
    var score     = result.score;
    var riskLevel = result.risk_level;
    var color     = RISK_COLORS[riskLevel] || '#555555';

    var bar = _scoreBar(score);

    var section = CardService.newCardSection();

    section.addWidget(
      CardService.newTextParagraph()
        .setText(
          '<b><font color="' + color + '" size="24">' + score + ' / 100</font></b>'
        )
    );

    section.addWidget(
      CardService.newTextParagraph().setText(bar)
    );

    section.addWidget(
      CardService.newTextParagraph()
        .setText('<b><font color="' + color + '">' + riskLevel + ' RISK — ' + _escapeText(result.verdict) + '</font></b>')
    );

    section.addWidget(
      CardService.newTextParagraph()
        .setText(_escapeText(result.summary))
    );

    return section;
  }

  function _buildSignalsSection(signals) {
    var section = CardService.newCardSection()
      .setHeader('Detected Signals (' + signals.length + ')');

    if (signals.length === 0) {
      section.addWidget(
        CardService.newTextParagraph().setText('✅ No threat signals detected.')
      );
      return section;
    }

    // Sort: highest severity first
    var ordered = signals.slice().sort(function (a, b) {
      return b.weight - a.weight;
    });

    ordered.forEach(function (signal) {
      var icon = SEVERITY_ICONS[signal.severity] || '⚪';
      section.addWidget(
        CardService.newKeyValue()
          .setTopLabel(icon + '  ' + _escapeText(signal.name))
          .setContent(_escapeText(signal.description))
          .setMultiline(true)
      );
    });

    return section;
  }

  function _buildFooterSection() {
    return CardService.newCardSection()
      .addWidget(
        CardService.newTextButton()
          .setText('🔄  Analyze Again')
          .setOnClickAction(
            CardService.newAction().setFunctionName('buildCard')
          )
      );
  }

  /** Render a simple ASCII progress bar for the score (0–100). */
  function _scoreBar(score) {
    var filled = Math.round(score / 10);
    var empty  = 10 - filled;
    return '▓'.repeat(filled) + '░'.repeat(empty) + '  ' + score + '%';
  }

  /** Sanitize user-derived text before placing it in a Card widget. */
  function _escapeText(text) {
    if (!text) return '';
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  return { fromResult: fromResult, fromError: fromError };
})();
