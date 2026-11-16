/** Private Accounts storage. CryptoKey uses IndexedDB structured cloning, never export. */
export const SESSION_DATABASE = 'webos-account-session-v1';
export function createSessionStore(scope) {
  let opening;
  function database() {
    return opening ||= new Promise((resolve, reject) => {
      let settled = false;
      const fail = () => { settled = true; clearTimeout(timer); reject(Error('Browser sign-in storage unavailable.')); };
      const timer = setTimeout(fail, 10000);
      let request;
      try { request = indexedDB.open(SESSION_DATABASE, 1); } catch { fail(); return; }
      request.onupgradeneeded = () => request.result.createObjectStore('sessions');
      request.onerror = request.onblocked = fail;
      request.onsuccess = () => {
        const db = request.result;
        if (settled) { db.close(); return; }
        settled = true; clearTimeout(timer);
        db.onversionchange = () => { db.close(); opening = null; };
        resolve(db);
      };
    });
  }
  async function transaction(mode, operation) {
    const db = await database();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('sessions', mode), store = tx.objectStore('sessions');
      let result;
      tx.oncomplete = () => resolve(result);
      tx.onabort = tx.onerror = () => reject(Error('Browser sign-in storage unavailable.'));
      operation(store, value => { result = value; });
    });
  }
  return Object.freeze({
    read: () => transaction('readonly', (store, done) => {
      const request = store.get(scope); request.onsuccess = () => done(request.result ?? null);
    }),
    write: record => transaction('readwrite', store => { store.put(record, scope); }),
    remove: id => transaction('readwrite', (store, done) => {
      const request = store.get(scope);
      request.onsuccess = () => {
        // An old tab cannot erase a newer account's remembered sign-in.
        if (request.result?.id === id) { store.delete(scope); done(true); }
        else done(false);
      };
    })
  });
}
