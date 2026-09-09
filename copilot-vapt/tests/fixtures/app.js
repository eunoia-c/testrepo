axios.interceptors.request.use(function (cfg) {
  cfg.headers.Authorization = 'Bearer ' + localStorage.getItem('access_token');
  return cfg;
});

async function loadCase(id) {
  const r = await fetch(`/api/v1/cases/${id}`, {
    method: 'GET',
    headers: { 'Authorization': 'Bearer ' + tok, 'Content-Type': 'application/json' },
    credentials: 'include'
  });
  return r.json();
}

function publicLookup(zip) {
  return fetch('/api/v1/public/branches?zip=' + zip, { credentials: 'omit' });
}

$.ajax({ url: '/legacy/Report.aspx?id=1', type: 'POST', data: { q: 1 } });

$.get('/api/v2/notifications/unread', function (d) { render(d); });

var xhr = new XMLHttpRequest();
xhr.open('DELETE', '/api/v1/admin/users/' + uid, true);
xhr.send();

Sys.Net.WebServiceProxy.invoke("/Services/AccountService.asmx", "GetBalance", false, {acct: a});

PageMethods.ExportAll(onDone);

const WS = new WebSocket('/socket/notify');

// DOM XSS fixtures
document.getElementById('out').innerHTML = location.hash.substring(1);
var q = new URLSearchParams(location.search).get('q');
$('#results').html(q);
var safe = location.search;
document.getElementById('t').textContent = safe;
el.innerHTML = DOMPurify.sanitize(userInput);
eval(localStorage.getItem('cfg'));
setTimeout('doThing(' + window.name + ')', 10);
