/* AWARENESS — компактный клиент Supabase (Auth + REST) без внешних зависимостей.
   Поддерживает ровно то, что использует приложение. */
(function () {
  const LS_KEY = 'awareness-session';
  const nowSec = () => Math.floor(Date.now() / 1000);
  const errOf = (j, status) => ({
    message: (j && (j.error_description || j.msg || j.message || j.error)) || ('HTTP ' + status),
    status, code: j && (j.code || j.error_code)
  });

  function createClient(url, key) {
    url = String(url).replace(/\/+$/, '');
    let session = null;
    try { session = JSON.parse(localStorage.getItem(LS_KEY) || 'null'); } catch (e) { session = null; }
    const listeners = [];
    const emit = (ev) => listeners.forEach(cb => { try { cb(ev, session); } catch (e) { console.error(e); } });
    const save = (s) => {
      session = s;
      try { s ? localStorage.setItem(LS_KEY, JSON.stringify(s)) : localStorage.removeItem(LS_KEY); } catch (e) {}
    };
    const toSession = (j) => ({
      access_token: j.access_token, refresh_token: j.refresh_token,
      expires_at: j.expires_at || (nowSec() + (Number(j.expires_in) || 3600)), user: j.user || null
    });

    async function raw(path, opts = {}, useToken = true) {
      const headers = Object.assign({ apikey: key, 'Content-Type': 'application/json' }, opts.headers || {});
      headers.Authorization = 'Bearer ' + ((useToken && session && session.access_token) || key);
      let res;
      try { res = await fetch(url + path, Object.assign({}, opts, { headers })); }
      catch (e) { return { data: null, error: { message: 'Failed to fetch' } }; }
      const text = await res.text();
      let j = null; try { j = text ? JSON.parse(text) : null; } catch (e) { j = null; }
      if (!res.ok) return { data: null, error: errOf(j, res.status), status: res.status };
      return { data: j, error: null, status: res.status };
    }

    let refreshing = null;
    async function refresh() {
      if (!session || !session.refresh_token) return false;
      if (!refreshing) refreshing = (async () => {
        const r = await raw('/auth/v1/token?grant_type=refresh_token',
          { method: 'POST', body: JSON.stringify({ refresh_token: session.refresh_token }) }, false);
        if (r.error) {
          if (r.status && r.status < 500) { save(null); emit('SIGNED_OUT'); }
          return false;
        }
        save(toSession(r.data)); emit('TOKEN_REFRESHED'); return true;
      })().finally(() => { refreshing = null; });
      return refreshing;
    }
    async function ensureFresh() {
      if (session && session.expires_at && session.expires_at - 60 < nowSec()) await refresh();
    }
    async function api(path, opts) {
      await ensureFresh();
      let r = await raw(path, opts);
      if (r.status === 401 && session && session.refresh_token && await refresh()) r = await raw(path, opts);
      return r;
    }
    setInterval(() => { if (session && session.expires_at - 300 < nowSec()) refresh(); }, 60000);

    // Сессия из ссылки в письме (восстановление пароля).
    let recoveryPending = null;
    if (/access_token=/.test(location.hash)) {
      const p = new URLSearchParams(location.hash.slice(1));
      const s = toSession({
        access_token: p.get('access_token'), refresh_token: p.get('refresh_token'),
        expires_in: p.get('expires_in'), expires_at: Number(p.get('expires_at')) || undefined
      });
      save(s);
      const type = p.get('type');
      try { history.replaceState(null, '', location.pathname + location.search); } catch (e) {}
      recoveryPending = (async () => {
        const u = await raw('/auth/v1/user', { method: 'GET' });
        if (!u.error) save(Object.assign({}, session, { user: u.data }));
        setTimeout(() => emit(type === 'recovery' ? 'PASSWORD_RECOVERY' : 'SIGNED_IN'), 0);
      })();
    }

    const auth = {
      onAuthStateChange(cb) { listeners.push(cb); return { data: { subscription: { unsubscribe() { const i = listeners.indexOf(cb); if (i >= 0) listeners.splice(i, 1); } } } }; },
      async getSession() { if (recoveryPending) await recoveryPending; await ensureFresh(); return { data: { session }, error: null }; },
      async getUser() {
        if (!session) return { data: { user: null }, error: null };
        const r = await api('/auth/v1/user', { method: 'GET' });
        if (r.error) return { data: { user: session.user }, error: r.error };
        save(Object.assign({}, session, { user: r.data })); return { data: { user: r.data }, error: null };
      },
      async signInWithPassword({ email, password }) {
        const r = await raw('/auth/v1/token?grant_type=password', { method: 'POST', body: JSON.stringify({ email, password }) }, false);
        if (r.error) return { data: { session: null }, error: r.error };
        save(toSession(r.data)); emit('SIGNED_IN'); return { data: { session }, error: null };
      },
      async signOut() {
        if (session) await raw('/auth/v1/logout', { method: 'POST' });
        save(null); emit('SIGNED_OUT'); return { error: null };
      },
      async resetPasswordForEmail(email, opts = {}) {
        const q = opts.redirectTo ? '?redirect_to=' + encodeURIComponent(opts.redirectTo) : '';
        const r = await raw('/auth/v1/recover' + q, { method: 'POST', body: JSON.stringify({ email }) }, false);
        return { data: {}, error: r.error };
      },
      async updateUser(attrs) {
        const r = await api('/auth/v1/user', { method: 'PUT', body: JSON.stringify(attrs) });
        if (!r.error) save(Object.assign({}, session, { user: r.data }));
        return { data: { user: r.data }, error: r.error };
      }
    };

    class Query {
      constructor(table) { this.t = table; this.op = null; this.cols = null; this.filters = []; this.ord = null; this.rng = null; this.body = null; }
      select(cols = '*') { this.cols = cols; if (!this.op) this.op = 'select'; return this; }
      insert(body) { this.op = 'insert'; this.body = body; return this; }
      upsert(body) { this.op = 'upsert'; this.body = body; return this; }
      update(body) { this.op = 'update'; this.body = body; return this; }
      delete() { this.op = 'delete'; return this; }
      eq(col, val) { this.filters.push(encodeURIComponent(col) + '=eq.' + encodeURIComponent(val)); return this; }
      order(col, o = {}) { this.ord = col + '.' + (o.ascending === false ? 'desc' : 'asc'); return this; }
      range(a, b) { this.rng = [a, b]; return this; }
      async run() {
        const qs = [];
        if (this.cols && this.op === 'select') qs.push('select=' + encodeURIComponent(this.cols));
        if (this.cols && this.op !== 'select') qs.push('select=' + encodeURIComponent(this.cols));
        if (this.ord) qs.push('order=' + this.ord);
        qs.push(...this.filters);
        const path = '/rest/v1/' + this.t + (qs.length ? '?' + qs.join('&') : '');
        const headers = {};
        let method = 'GET', body;
        if (this.op === 'select' || !this.op) {
          if (this.rng) { headers['Range-Unit'] = 'items'; headers.Range = this.rng[0] + '-' + this.rng[1]; }
        } else if (this.op === 'insert') {
          method = 'POST'; body = JSON.stringify(this.body); headers.Prefer = this.cols ? 'return=representation' : 'return=minimal';
        } else if (this.op === 'upsert') {
          method = 'POST'; body = JSON.stringify(this.body); headers.Prefer = 'resolution=merge-duplicates,' + (this.cols ? 'return=representation' : 'return=minimal');
        } else if (this.op === 'update') {
          method = 'PATCH'; body = JSON.stringify(this.body); headers.Prefer = 'return=minimal';
        } else if (this.op === 'delete') {
          method = 'DELETE'; headers.Prefer = 'return=minimal';
        }
        const r = await api(path, { method, headers, body });
        return { data: r.error ? null : (r.data ?? null), error: r.error };
      }
      then(res, rej) { return this.run().then(res, rej); }
    }

    return {
      auth,
      from: (t) => new Query(t),
      async rpc(fn, args) {
        const r = await api('/rest/v1/rpc/' + fn, { method: 'POST', body: JSON.stringify(args || {}) });
        return { data: r.data, error: r.error };
      },
      // Мгновенные обновления заменены периодической синхронизацией в приложении.
      channel() { const c = { on() { return c; }, subscribe() { return c; } }; return c; }
    };
  }

  window.supabase = { createClient };
})();
