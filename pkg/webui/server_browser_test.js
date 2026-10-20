(async function() {
  var result = document.createElement('pre');
  result.id = 'webui-test-result';
  document.body.appendChild(result);
  var timings = {};
  var reportResult = window.fetch.bind(window);
  var renderCount = 0;
  var originalRenderRows = renderRows;
  renderRows = function() { renderCount += 1; originalRenderRows(); };

  function assert(condition, message) {
    if (!condition) throw new Error(message);
  }
  function delay(ms) {
    return new Promise(function(resolve) { window.setTimeout(resolve, ms); });
  }
  async function waitFor(predicate, message) {
    for (var i = 0; i < 500; i += 1) {
      if (predicate()) return;
      await delay(20);
    }
    throw new Error(message);
  }
  async function rendered() {
    await waitFor(function() { return renderTimer === null; }, 'render did not finish');
    assert(tableBody.children.length <= 100, 'table exceeded the 100-row rendering bound');
  }
  function emit(name, item) {
    source.dispatchEvent(new MessageEvent(name, { data: JSON.stringify(item) }));
  }
  function firstSecret() {
    return tableBody.querySelector('button[data-copy]').dataset.copy;
  }

  try {
    var started = performance.now();
    await waitFor(function() { return state.all.length === 2000 && state.notificationsReady; }, 'SSE replay did not deliver 2,000 findings');
    await rendered();
    timings.reloadMillis = Math.round(performance.now() - started);
    assert(timings.reloadMillis < 5000, '2,000-finding reload took over five seconds');
    assert(renderCount <= 2, 'replay rebuilt the table ' + renderCount + ' times');
    assert(tableBody.children.length === 100, 'first page must show 100 findings');
    assert(firstSecret().startsWith('fixture-value-2000'), 'findings must be ordered by precise timestamp, newest first');
    assert(pageStatus.textContent === 'Showing 1-100 of 2000 findings (2000 total)', 'incorrect first-page count');
    assert(previousPage.disabled && !nextPage.disabled, 'incorrect first-page navigation');
    assert(connectionState.textContent === 'complete', 'completed SSE replay lost completion state');
    assert(window.testNotifications.length === 0, 'historical findings triggered notifications');
    var all = filteredFindings().slice();
    assert(filteredFindings() === filteredFindings(), 'filtered findings should be cached');
    assert(Array.from(summaryCards.querySelectorAll('strong')).map(function(el) { return el.textContent; }).join(',') === '667,667,0,0,666', 'incorrect full-scan summary');

    nextPage.click();
    assert(firstSecret().startsWith('fixture-value-1900'), 'next page did not advance');
    assert(pageStatus.textContent.startsWith('Showing 101-200'), 'incorrect second-page count');
    previousPage.click();
    assert(firstSecret().startsWith('fixture-value-2000'), 'previous page did not return');
    for (var page = 1; page < 20; page += 1) nextPage.click();
    assert(nextPage.disabled && !previousPage.disabled, 'last-page navigation should stop at the boundary');
    assert(firstSecret().startsWith('fixture-value-0100'), 'last page omitted findings');

    started = performance.now();
    document.getElementById('severity-trigger').click();
    document.querySelector('#severity-options [data-value="verified"]').click();
    document.querySelector('#severity-options [data-value="high"]').click();
    document.getElementById('type-trigger').click();
    document.querySelector('#type-options [data-value="archive"]').click();
    await rendered();
    timings.filterMillis = Math.round(performance.now() - started);
    assert(timings.filterMillis < 1000, 'multi-select filter took over one second');
    var expected = all.filter(function(item) {
      return ['verified', 'high'].includes(item.confidence) && item.type === 'archive';
    });
    assert(filteredFindings().length === expected.length, 'multi-select filters did not cover all pages');
    assert(state.page === 0 && previousPage.disabled, 'filter changes must return to the first page');
    assert(firstSecret() === expected[0].value, 'filtered results lost timestamp order');
    assert(summaryCards.querySelector('strong').textContent === '667', 'filter changed full-scan summary');

    resetButton.click();
    await rendered();
    var searches = [
      ['FIXTURE-RULE-0001', 'fixture-value-0001'],
      ['fixture-value-0002', 'fixture-value-0002'],
      ['https://example.test/jobs/0003', 'fixture-value-0003'],
      ['PROJECT-07', null],
      ['archive', null]
    ];
    for (var search of searches) {
      searchFilter.value = search[0];
      searchFilter.dispatchEvent(new Event('input'));
      await rendered();
      assert(filteredFindings().length > 0, 'search failed for ' + search[0]);
      if (search[1]) assert(firstSecret().startsWith(search[1]), 'search omitted an off-page finding');
    }
    searchFilter.value = 'not-a-fixture-match';
    searchFilter.dispatchEvent(new Event('input'));
    await rendered();
    assert(tableBody.textContent.includes('No findings match the current filters.'), 'filtered empty state missing');
    assert(previousPage.disabled && nextPage.disabled, 'empty results should disable pagination');

    resetFilters();
    await rendered();
    nextPage.click();
    var exportBody;
    var originalFetch = window.fetch;
    var originalClick = HTMLAnchorElement.prototype.click;
    window.fetch = function(url, options) {
      assert(url === '/api/export.csv', 'CSV request used an unexpected URL');
      exportBody = JSON.parse(options.body);
      return Promise.resolve({ ok: true, blob: function() { return Promise.resolve(new Blob(['fixture CSV'])); } });
    };
    HTMLAnchorElement.prototype.click = function() {};
    exportCSVButton.click();
    assert(exportBody.length === 2000, 'CSV export was limited to the current page');
    assert(exportBody[0].id === '2000' && exportBody[1999].id === '1', 'CSV lost order or finding fields');
    assert(!('search' in exportBody[0]) && !('item' in exportBody[0]), 'CSV payload leaked internal indexing fields');
    // Export immediately after typing, before the scheduled table render.
    searchFilter.value = 'PROJECT-07';
    searchFilter.dispatchEvent(new Event('input'));
    exportCSVButton.click();
    assert(exportBody.length === 100 && exportBody.every(function(item) { return item.details.project === 'project-07'; }), 'CSV did not use the latest filters');
    await delay(20);
    window.fetch = originalFetch;
    HTMLAnchorElement.prototype.click = originalClick;
    await rendered();
    resetFilters();
    await rendered();

    // Reconnection replays immutable IDs without rebuilding, recounting, or notifying.
    var beforeReplay = renderCount;
    source.onopen();
    all.forEach(function(item) { emit('finding', item); });
    assert(renderCount === beforeReplay && renderTimer === null, 'duplicate replay scheduled table work');
    assert(state.all.length === 2000, 'reconnect replay duplicated findings');
    var liveTime = Date.now() + 1000;
    emit('finding', { id: '2001', time: new Date(liveTime).toISOString(), timestampMillis: liveTime, confidence: 'verified', type: 'log', value: 'fixture-replay-new' });
    assert(window.testNotifications.length === 0, 'replayed finding triggered a notification');
    assert(renderTimer === null, 'replay should wait for replay-complete before rendering');
    emit('replay-complete', null);
    await rendered();
    assert(state.all.length === 2001, 'reconnect omitted a new finding');
    for (var i = 0; i < 200; i += 1) {
      emit('finding', { id: String(2002 + i), time: new Date(liveTime + i + 1).toISOString(), timestampMillis: liveTime + i + 1, confidence: 'verified', type: 'log', value: 'fixture-live-' + i });
    }
    assert(renderCount === beforeReplay + 1, 'live burst rendered synchronously per finding');
    await rendered();
    assert(renderCount === beforeReplay + 2, 'live burst was not coalesced into one render');
    assert(state.all.length === 2201 && filteredFindings().length === 2201, 'live updates lost findings or cached stale results');
    assert(firstSecret() === 'fixture-live-199', 'live finding did not invalidate timestamp ordering');
    assert(summaryCards.querySelector('strong').textContent === '868', 'live or duplicate updates corrupted summary counts');
    assert(window.testNotifications.length === 200, 'live findings lost notifications');
    assert(window.testNotifications.every(function(n) { return !n.options.body.includes('fixture-live'); }), 'notification text exposed a secret');
    for (var lastPage = 0; lastPage < 22; lastPage += 1) nextPage.click();
    assert(nextPage.disabled && tableBody.children.length === 1, 'partial last page must show the final finding exactly once');
    assert(pageStatus.textContent === 'Showing 2201-2201 of 2201 findings (2201 total)', 'partial-page count is incorrect');
    emit('done', { elapsedMillis: 42135 });
    await rendered();
    assert(connectionState.textContent === 'complete' && elapsedTime.textContent === 'Elapsed 00:00:42', 'completion or elapsed-time state regressed');
    result.textContent = 'PASS ' + JSON.stringify(timings) + ', bounded rows and batched replay/live updates';
  } catch (error) {
    result.textContent = 'FAIL ' + error.stack;
  } finally {
    await reportResult('/test-result', { method: 'POST', body: result.textContent });
  }
})();
