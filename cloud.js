'use strict';
/* ======================= 雲端同步（Firebase） =======================
   一人匯入清冊，所有人共用；初盤、複盤、清冊外條碼、標籤紀錄、盤點過程即時同步。
   資料結構（Firestore）：
     ws/main                         共用設定：公司、清冊來源、清冊版本、目前盤點 id
     ws/main/assets/{000…}           財產清冊（每份 400 筆，JSON 字串）；recon 為清冊差異
     ws/main/labels/{uid}            每人的標籤列印／黏貼紀錄
     audits/{id}                     一期盤點：名稱、基準日、階段、結束時間
     audits/{id}/members/{uid}       每人的初盤 s1、複盤 s2、清冊外 ex
     audits/{id}/logs/{uid}          每人的盤點過程
     audits/{id}/assets/{000…}       結束時的清冊快照（供日後匯出）
   每個人只寫自己的文件（修改他人紀錄時才更新對方文件），避免多人同時寫入同一文件。 */
(function(){
  const cfg = window.FIREBASE_CONFIG;
  if(!cfg || !window.firebase){ setCloudUi('off'); return; }

  const DOMAIN = String(window.FIREBASE_ALLOWED_DOMAIN || 'aetherai.com').toLowerCase();
  firebase.initializeApp(cfg);
  const auth = firebase.auth(), db = firebase.firestore();
  db.enablePersistence({synchronizeTabs:true}).catch(() => {});   // 離線時也能盤點，連線後自動上傳
  const FV = firebase.firestore.FieldValue, FP = firebase.firestore.FieldPath;
  const WS = db.collection('ws').doc('main');
  const CHUNK = 400;
  const now = () => new Date().toISOString();
  const J = o => JSON.stringify(o), P = s => { try{ return JSON.parse(s); }catch(e){ return null; } };
  const strip = o => { const {uid, _key, _affixUid, ...rest} = o || {}; return rest; };

  let user = null, meta = null, auditId = null, loadedRev = null;
  let wsUnsubs = [], auditUnsubs = [];
  let memberDocs = new Map(), labelDocs = new Map(), logDocs = new Map();
  let netState = {fromCache:false, pending:false};

  const api = {
    ready:false, email:'', name:'', uid:'',
    get auditId(){ return auditId; },
    putScan, delScan, putExtra, delExtra, log, putAudit, putMeta, uploadAssets, uploadAssetsSoon,
    labelsPrinted, labelAffix, unaffix, resetLabels, closeAudit, listArchives, loadArchive, deleteArchive, signOut,
    // 標籤驗證碼與標籤管理員
    hashes:{}, admins:[], isLabelAdmin:() => false, ensureCodes, regenerateCode, codeOf:id => secrets[id] || '', saveAdmins, resetLabelFor
  };

  /* ---------- 登入 ---------- */
  $('#btnCloudLogin').addEventListener('click', signIn);
  $('#btnCloudLogin2').addEventListener('click', signIn);
  $('#btnCloudLogout').addEventListener('click', () => { if(confirm('確定登出？登出後無法同步盤點資料。')) signOut(); });
  async function signIn(){
    const p = new firebase.auth.GoogleAuthProvider();
    p.setCustomParameters({hd:DOMAIN, prompt:'select_account'});
    // iPhone 主畫面 App 的彈出視窗常無法回傳登入結果，改用整頁跳轉
    if(typeof IS_IOS !== 'undefined' && IS_IOS && IS_STANDALONE) return auth.signInWithRedirect(p);
    try{ await auth.signInWithPopup(p); }
    catch(e){
      if(['auth/popup-blocked', 'auth/operation-not-supported-in-this-environment', 'auth/cancelled-popup-request'].includes(e.code)) return auth.signInWithRedirect(p);
      if(e.code !== 'auth/popup-closed-by-user') alert('登入失敗：' + (e.message || e.code));
    }
  }
  async function signOut(){ teardown(); CLOUD = null; await auth.signOut(); setCloudUi('out'); render(); }

  auth.onAuthStateChanged(async u => {
    teardown();
    if(!u){ user = null; CLOUD = null; setCloudUi('out'); render(); return; }
    const email = (u.email || '').toLowerCase();
    if(!email.endsWith('@' + DOMAIN)){
      alert(`請使用公司帳號（@${DOMAIN}）登入。`); await auth.signOut(); return;
    }
    user = u;
    Object.assign(api, {email, name:u.displayName || email.split('@')[0], uid:u.uid, ready:false});
    CLOUD = api;
    // 盤點人預設帶入帳號 @ 前的文字；使用者手動改過的姓名不覆蓋（舊版自動帶入的顯示名稱會換成帳號名稱）
    const auto = email.split('@')[0];
    if(!S.prefs.by || S.prefs.by === S.prefs.byAuto || S.prefs.by === u.displayName){
      S.prefs.by = auto; S.prefs.byAuto = auto; save();
      if($('#scanBy')) $('#scanBy').value = auto;
    }
    setCloudUi('sync', '連線中…');
    subscribeWs();
  });
  window.addEventListener('online', () => updateNet());
  window.addEventListener('offline', () => updateNet());

  function teardown(){
    wsUnsubs.forEach(f => f()); auditUnsubs.forEach(f => f());
    if(secretUnsub){ secretUnsub(); secretUnsub = null; }
    secrets = {}; api.hashes = {}; api.admins = [];
    wsUnsubs = []; auditUnsubs = []; meta = null; auditId = null; loadedRev = null;
    memberDocs = new Map(); labelDocs = new Map(); logDocs = new Map();
    api.ready = false;
  }

  /* ---------- 訂閱：共用設定與清冊 ---------- */
  /* ---------- 標籤驗證碼與標籤管理員 ----------
     labelSecrets/main：財產編號 → 驗證碼（只有標籤管理員能讀寫）
     labelHashes/main ：財產編號 → SHA-256(編號:驗證碼)（所有人可讀，用來驗證標籤真假）
     roles/main       ：labelAdmins（標籤管理員 email 清單）；OWNER 固定為管理員（寫在安全規則中） */
  const OWNER = 'wesker.wei@aetherai.com';
  let secrets = {}, secretUnsub = null;
  const ROLES = db.collection('roles').doc('main');
  const HASHES = db.collection('labelHashes').doc('main');
  const SECRETS = db.collection('labelSecrets').doc('main');
  api.isLabelAdmin = () => !!user && (api.email === OWNER || api.admins.includes(api.email));
  function subscribeLabelSecurity(){
    wsUnsubs.push(ROLES.onSnapshot(snap => {
      api.admins = ((snap.data() || {}).labelAdmins || []).map(x => String(x).toLowerCase());
      if(api.isLabelAdmin() && !secretUnsub){
        secretUnsub = SECRETS.onSnapshot(sn => { secrets = (sn.data() || {}).codes || {}; refresh(); }, e => console.warn('secrets', e));
      } else if(!api.isLabelAdmin() && secretUnsub){ secretUnsub(); secretUnsub = null; secrets = {}; }
      refresh();
    }, e => console.warn('roles', e)));
    wsUnsubs.push(HASHES.onSnapshot(snap => { api.hashes = (snap.data() || {}).h || {}; refresh(); }, e => console.warn('hashes', e)));
  }
  // 14 碼隨機驗證碼（32 個不易混淆的字元，約 70 位元，無法猜測或暴力推算）
  const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  function newCode(){
    const b = new Uint8Array(14); crypto.getRandomValues(b);
    return [...b].map(x => ALPHA[x & 31]).join('');
  }
  // 為還沒有驗證碼的財產產生驗證碼（列印時呼叫）；已有的沿用，確保同一財產每次印出相同標籤
  async function ensureCodes(ids){
    if(!api.isLabelAdmin()) throw new Error('需要標籤管理員權限');
    const snap = await SECRETS.get({source:'server'}).catch(() => SECRETS.get());
    const cur = (snap.data() || {}).codes || {};
    const add = {}, addH = {};
    for(const id of ids) if(!cur[id]){ const c = newCode(); add[id] = c; addH[id] = await labelHash(id, c); }
    if(Object.keys(add).length){
      const b = db.batch();
      b.set(SECRETS, {codes:add, updatedAt:now(), updatedBy:api.email}, {merge:true});
      b.set(HASHES, {h:addH, updatedAt:now()}, {merge:true});
      await b.commit();
    }
    secrets = {...cur, ...add};
    return secrets;
  }
  // 重新產生驗證碼：舊標籤立即失效
  async function regenerateCode(id){
    if(!api.isLabelAdmin()) throw new Error('需要標籤管理員權限');
    const c = newCode(), h = await labelHash(id, c);
    const b = db.batch();
    b.set(SECRETS, {codes:{[id]:c}, updatedAt:now(), updatedBy:api.email}, {merge:true});
    b.set(HASHES, {h:{[id]:h}, updatedAt:now()}, {merge:true});
    await b.commit();
    secrets[id] = c; api.hashes[id] = h;
    await resetLabelFor(id);
    return c;
  }
  // 清除某財產的列印／黏貼紀錄（重新產生驗證碼後需重印）
  async function resetLabelFor(id){
    for(const [uid, d] of labelDocs) if(d.map && d.map[id]) await WS.collection('labels').doc(uid).update(new FP('map', id), FV.delete()).catch(fail);
  }
  async function saveAdmins(list){
    if(!api.isLabelAdmin()) throw new Error('需要標籤管理員權限');
    const clean = [...new Set(list.map(x => String(x).trim().toLowerCase()).filter(x => x.endsWith('@' + DOMAIN) && x !== OWNER))];
    await ROLES.set({labelAdmins:clean, updatedAt:now(), updatedBy:api.email}, {merge:true});
  }

  function subscribeWs(){
    subscribeLabelSecurity();
    wsUnsubs.push(WS.onSnapshot({includeMetadataChanges:true}, async snap => {
      netState.fromCache = snap.metadata.fromCache; updateNet();
      if(!snap.exists){
        if(snap.metadata.fromCache) return;          // 等伺服器回應，避免誤判雲端是空的
        return initCloud();
      }
      meta = snap.data();
      S.company = meta.company || S.company; S.source = meta.source || ''; S.deptSource = meta.deptSource || '';
      if(meta.assetsRev !== loadedRev) await loadAssets(meta.assetsRev);
      if(meta.currentAuditId && meta.currentAuditId !== auditId) subscribeAudit(meta.currentAuditId);
      refresh();
    }, err => setCloudUi('error', '無法讀取雲端資料：' + err.message)));
    wsUnsubs.push(WS.collection('labels').onSnapshot(qs => {
      labelDocs = new Map(qs.docs.map(d => [d.id, d.data()]));
      rebuildLabels(); refresh();
    }));
  }

  // 雲端第一次使用：把這台裝置的清冊與資料上傳成為共用資料
  async function initCloud(){
    if(!S.assets.length){
      alert('雲端還沒有財產清冊。請由負責人到「設定 → 匯入財產清冊」匯入，匯入後所有人都會自動取得。');
    } else if(!confirm(`雲端還沒有資料。要把這台裝置的財產清冊（${S.assets.length} 筆）與目前的盤點、標籤紀錄上傳成為全公司共用的資料嗎？\n\n選「取消」會登出，這台裝置維持單機使用。`)){
      return signOut();
    }
    const id = 'A' + Date.now();
    const b = db.batch();
    b.set(db.collection('audits').doc(id), {name:S.audit.name || guessAuditName(), date:S.audit.date || '', startedAt:S.audit.startedAt || now(), round:S.round || 1, round1ClosedAt:S.audit.round1ClosedAt || '', createdAt:now(), createdBy:api.email});
    const m = {}; for(const r of [1, 2]) for(const [k, v] of Object.entries(SC(r))) (m['s' + r] = m['s' + r] || {})[k] = J(strip(v));
    m.ex = {}; for(const x of S.extras) m.ex[`${exRound(x)}|${x.code}`] = J(strip(x));
    b.set(db.collection('audits').doc(id).collection('members').doc(api.uid), {name:api.name, email:api.email, updatedAt:now(), ...m});
    if(S.log.length) b.set(db.collection('audits').doc(id).collection('logs').doc(api.uid), {events:S.log.map(J)});
    const lm = {}; for(const [k, v] of Object.entries(S.labels)) lm[k] = J(strip(v));
    if(Object.keys(lm).length) b.set(WS.collection('labels').doc(api.uid), {name:api.name, email:api.email, map:lm});
    await b.commit();
    await uploadAssets({currentAuditId:id});
    toast('已建立雲端共用資料');
  }

  async function loadAssets(rev){
    let qs;
    try{ qs = await WS.collection('assets').get({source:'server'}); }catch(e){ qs = await WS.collection('assets').get(); }
    const docs = qs.docs.filter(d => d.id !== 'recon' && d.data().rev === rev).sort((a, b) => a.id.localeCompare(b.id));
    S.assets = docs.flatMap(d => P(d.data().json) || []);
    const rc = qs.docs.find(d => d.id === 'recon');
    S.recon = rc && rc.data().rev === rev ? P(rc.data().json) : null;
    loadedRev = rev; reindex(); save();
  }

  // 寫入整份清冊（匯入、修改部門等）：清冊一次寫入，所有人收到新版本後重新載入
  async function uploadAssets(extraMeta){
    const rev = Date.now();
    const old = await WS.collection('assets').get();
    const b = db.batch();
    old.docs.forEach(d => b.delete(d.ref));
    for(let i = 0; i * CHUNK < S.assets.length; i++){
      b.set(WS.collection('assets').doc(String(i).padStart(3, '0')), {rev, json:J(S.assets.slice(i * CHUNK, (i + 1) * CHUNK))});
    }
    if(S.recon) b.set(WS.collection('assets').doc('recon'), {rev, json:J(S.recon)});
    b.set(WS, {company:S.company, source:S.source || '', deptSource:S.deptSource || '', assetsRev:rev, assetCount:S.assets.length,
      updatedAt:now(), updatedBy:api.email, ...(extraMeta || {})}, {merge:true});
    loadedRev = rev;              // 自己寫的版本不必再下載
    await b.commit();
  }
  let upT = null;
  function uploadAssetsSoon(){ clearTimeout(upT); upT = setTimeout(() => uploadAssets().catch(e => toast('清冊上傳失敗：' + e.message)), 800); }

  /* ---------- 訂閱：目前這一期盤點 ---------- */
  function subscribeAudit(id){
    auditUnsubs.forEach(f => f()); auditUnsubs = [];
    // 第一次切換到雲端時，本機若有雲端沒有的盤點紀錄，先備份到「紀錄」
    if(auditId === null && (Object.keys(S.scans).length || Object.keys(S.scans2).length)){
      try{ idb.put({...snapshot('checkpoint'), id:'H' + Date.now(), audit:{...S.audit, name:(S.audit.name || '') + '（切換雲端前本機備份）'}}); }catch(e){}
    }
    auditId = id;
    const A = db.collection('audits').doc(id);
    A.collection('members').doc(api.uid).set({name:api.name, email:api.email, updatedAt:now()}, {merge:true});
    auditUnsubs.push(A.onSnapshot(s => {
      const d = s.data() || {};
      S.audit = {name:d.name || '', year:d.year || null, kind:d.kind || '', date:d.date || '', startedAt:d.startedAt || '', round1ClosedAt:d.round1ClosedAt || ''};
      S.round = d.round === 2 ? 2 : 1;
      refresh();
    }));
    auditUnsubs.push(A.collection('members').onSnapshot({includeMetadataChanges:true}, qs => {
      netState.pending = qs.metadata.hasPendingWrites; netState.fromCache = qs.metadata.fromCache;
      memberDocs = new Map(qs.docs.map(d => [d.id, d.data()]));
      rebuildScans();
      api.ready = true; updateNet(); refresh();
    }));
    auditUnsubs.push(A.collection('logs').onSnapshot(qs => {
      logDocs = new Map(qs.docs.map(d => [d.id, d.data()]));
      rebuildLog(); refresh();
    }));
  }

  /* ---------- 由雲端文件組回畫面使用的資料 ---------- */
  function mergeScans(docs){
    const s1 = {}, s2 = {}, ex = [], exSeen = new Map();
    for(const [uid, d] of docs){
      for(const [r, out] of [[1, s1], [2, s2]]){
        for(const [id, js] of Object.entries(d['s' + r] || {})){
          const o = P(js); if(!o) continue; o.uid = uid;
          if(!out[id] || o.t < out[id].t) out[id] = o;       // 同一筆被多人盤到時，以最早的為準
        }
      }
      for(const [key, js] of Object.entries(d.ex || {})){
        const o = P(js); if(!o) continue; o.uid = uid; o._key = key;
        const k = `${exRound(o)}|${o.code}`, cur = exSeen.get(k);
        if(!cur || o.t < cur.t) exSeen.set(k, o);
      }
    }
    ex.push(...[...exSeen.values()].sort((a, b) => a.t.localeCompare(b.t)));
    return {s1, s2, ex};
  }
  function rebuildScans(){ const m = mergeScans(memberDocs); S.scans = m.s1; S.scans2 = m.s2; S.extras = m.ex; }
  function mergeLogs(docs){
    const seen = new Set(), out = [];
    for(const d of docs.values()) for(const js of d.events || []){ const e = P(js); if(e && !seen.has(e.k)){ seen.add(e.k); out.push(e); } }
    return out.sort((a, b) => a.t.localeCompare(b.t));
  }
  function rebuildLog(){ S.log = mergeLogs(logDocs); }
  function rebuildLabels(){
    const out = {};
    for(const [uid, d] of labelDocs){
      for(const [id, js] of Object.entries(d.map || {})){
        const l = P(js); if(!l) continue;
        const c = out[id] || (out[id] = {printCount:0});
        if(l.printedAt && (!c.printedAt || l.printedAt < c.printedAt)) c.printedAt = l.printedAt;
        if(l.lastPrintedAt && (!c.lastPrintedAt || l.lastPrintedAt > c.lastPrintedAt)) c.lastPrintedAt = l.lastPrintedAt;
        c.printCount += l.printCount || 0;
        if(l.affixedAt && (!c.affixedAt || l.affixedAt < c.affixedAt)){ c.affixedAt = l.affixedAt; c.affixedBy = l.affixedBy; c.affixMethod = l.affixMethod; c._affixUid = uid; }
      }
    }
    S.labels = out;
  }

  // 收到雲端更新時重繪畫面（節流；掃描頁只更新側欄，不清掉剛掃到的結果）
  let rT = null;
  function refresh(){
    clearTimeout(rT);
    rT = setTimeout(() => {
      reindex(); save();
      if(curView === 'scan'){ renderScanSide(); updateAuditorUi(); if(!$('#scanBy').value) $('#scanBy').value = S.prefs.by || ''; const st = stats(); $('#hdrSub').textContent = S.assets.length ? `${ROUND[S.round]} ${st.done}/${st.total}` : ''; }
      else if(!document.querySelector('dialog[open]')) render();
      updateNet();
    }, 250);
  }

  /* ---------- 寫入 ---------- */
  const A = () => db.collection('audits').doc(auditId);
  const fail = e => { console.warn(e); toast('雲端寫入失敗：' + (e.message || e.code)); };
  function putScan(r, id, obj){
    if(!auditId) return;
    const owner = obj.uid || api.uid;
    if(owner === api.uid) A().collection('members').doc(owner).set({['s' + r]:{[id]:J(strip(obj))}, updatedAt:now()}, {merge:true}).catch(fail);
    else A().collection('members').doc(owner).update(new FP('s' + r, id), J(strip(obj))).catch(fail);
  }
  function delScan(r, id){
    if(!auditId) return;
    for(const [uid, d] of memberDocs) if(d['s' + r] && d['s' + r][id]) A().collection('members').doc(uid).update(new FP('s' + r, id), FV.delete()).catch(fail);
  }
  function putExtra(x){
    if(!auditId) return;
    const owner = x.uid || api.uid, key = x._key || `${exRound(x)}|${x.code}`;
    if(owner === api.uid) A().collection('members').doc(owner).set({ex:{[key]:J(strip(x))}}, {merge:true}).catch(fail);
    else A().collection('members').doc(owner).update(new FP('ex', key), J(strip(x))).catch(fail);
  }
  function delExtra(x){
    if(!auditId) return;
    const key = x._key || `${exRound(x)}|${x.code}`;
    for(const [uid, d] of memberDocs) if(d.ex && d.ex[key]) A().collection('members').doc(uid).update(new FP('ex', key), FV.delete()).catch(fail);
  }
  function log(ev){ if(auditId) A().collection('logs').doc(api.uid).set({events:FV.arrayUnion(J(ev))}, {merge:true}).catch(fail); }
  function putAudit(fields){
    if(!auditId) return;
    const f = {}; for(const [k, v] of Object.entries(fields)) f[k] = v === null ? FV.delete() : v;
    A().set(f, {merge:true}).catch(fail);
  }
  function putMeta(fields){ WS.set(fields, {merge:true}).catch(fail); }

  // 標籤：只寫自己的文件；批次黏貼時合併成一次寫入
  const myLabel = id => P(((labelDocs.get(api.uid) || {}).map || {})[id]) || {printCount:0};
  function labelsPrinted(ids){
    const t = now(), map = {};
    for(const id of ids){ const l = myLabel(id); map[id] = J({...l, printedAt:l.printedAt || t, lastPrintedAt:t, printCount:(l.printCount || 0) + 1}); }
    WS.collection('labels').doc(api.uid).set({name:api.name, email:api.email, map}, {merge:true}).catch(fail);
  }
  let affixQ = {}, affixT = null;
  function labelAffix(id, l){
    affixQ[id] = J({...myLabel(id), affixedAt:l.affixedAt, affixedBy:l.affixedBy, affixMethod:l.affixMethod});
    clearTimeout(affixT);
    affixT = setTimeout(() => { const map = affixQ; affixQ = {}; WS.collection('labels').doc(api.uid).set({name:api.name, email:api.email, map}, {merge:true}).catch(fail); }, 300);
  }
  function unaffix(id){
    for(const [uid, d] of labelDocs){
      const l = P((d.map || {})[id]);
      if(l && l.affixedAt){ delete l.affixedAt; delete l.affixedBy; delete l.affixMethod; WS.collection('labels').doc(uid).update(new FP('map', id), J(l)).catch(fail); }
    }
  }
  async function resetLabels(){ const qs = await WS.collection('labels').get(); const b = db.batch(); qs.docs.forEach(d => b.delete(d.ref)); await b.commit(); }

  /* ---------- 結束本期、歷次紀錄 ---------- */
  async function closeAudit(summary, nextAudit){
    const old = auditId, OA = db.collection('audits').doc(old), nid = 'A' + Date.now();
    const b = db.batch();
    for(let i = 0; i * CHUNK < S.assets.length; i++) b.set(OA.collection('assets').doc(String(i).padStart(3, '0')), {json:J(S.assets.slice(i * CHUNK, (i + 1) * CHUNK))});
    if(S.recon) b.set(OA.collection('assets').doc('recon'), {json:J(S.recon)});
    b.set(OA, {closedAt:now(), closedBy:api.name, closedByEmail:api.email, summary:J(summary), round:S.round, source:S.source || '', company:S.company}, {merge:true});
    b.set(db.collection('audits').doc(nid), {...nextAudit, round:1, round1ClosedAt:'', createdAt:now(), createdBy:api.email});
    b.set(WS, {currentAuditId:nid}, {merge:true});
    await b.commit();
    subscribeAudit(nid);
  }
  async function listArchives(){
    const qs = await db.collection('audits').get();
    return qs.docs.map(d => ({id:d.id, ...d.data()})).filter(d => d.closedAt).map(d => ({
      id:'cloud:' + d.id, cloud:true, kind:'close', savedAt:d.closedAt, savedBy:d.closedBy || '',
      audit:{name:d.name, date:d.date, startedAt:d.startedAt, round1ClosedAt:d.round1ClosedAt, closedAt:d.closedAt},
      summary:P(d.summary) || {total:0, done:0, todo:0, extra:0, depts:[]}, log:[]
    }));
  }
  async function loadArchive(cid){
    const id = cid.replace(/^cloud:/, ''), OA = db.collection('audits').doc(id);
    const [d, as, ms, ls] = await Promise.all([OA.get(), OA.collection('assets').get(), OA.collection('members').get(), OA.collection('logs').get()]);
    const a = d.data() || {};
    const chunks = as.docs.filter(x => x.id !== 'recon').sort((x, y) => x.id.localeCompare(y.id));
    const rc = as.docs.find(x => x.id === 'recon');
    const m = mergeScans(new Map(ms.docs.map(x => [x.id, x.data()])));
    return {id:cid, cloud:true, kind:'close', savedAt:a.closedAt, savedBy:a.closedBy || '', company:a.company || S.company, source:a.source || '',
      audit:{name:a.name, year:a.year, kind:a.kind, date:a.date, startedAt:a.startedAt, round1ClosedAt:a.round1ClosedAt, closedAt:a.closedAt}, round:a.round,
      recon:rc ? P(rc.data().json) : null, assets:chunks.flatMap(x => P(x.data().json) || []),
      scans:m.s1, scans2:m.s2, extras:m.ex, log:mergeLogs(new Map(ls.docs.map(x => [x.id, x.data()]))), summary:P(a.summary) || {}};
  }
  async function deleteArchive(cid){
    const id = cid.replace(/^cloud:/, ''), OA = db.collection('audits').doc(id);
    const b = db.batch();
    for(const sub of ['assets', 'members', 'logs']) (await OA.collection(sub).get()).docs.forEach(d => b.delete(d.ref));
    b.delete(OA); await b.commit();
  }

  /* ---------- 連線狀態 ---------- */
  function updateNet(){
    if(!user) return;
    if(!navigator.onLine) setCloudUi('offline', '離線中：盤點資料會先存在這支手機，恢復網路後自動上傳');
    else if(!api.ready) setCloudUi('sync', '連線中…');
    else if(netState.pending) setCloudUi('sync', '上傳中…');
    else setCloudUi('on', `已同步・${memberDocs.size} 人參與本期盤點`);
  }
})();

function setCloudUi(state, text){
  const dot = $('#cloudDot'), st = $('#cloudStatus');
  const conf = !!window.FIREBASE_CONFIG;
  const label = {off:'', out:'☁ 未登入', sync:'☁ 同步中', on:'☁ 已同步', offline:'☁ 離線', error:'☁ 錯誤'}[state] || '';
  dot.textContent = label;
  $('#cloudCard').classList.toggle('hide', !conf);
  $('#cloudBanner').classList.toggle('hide', !(conf && state === 'out'));
  $('#btnCloudLogin').classList.toggle('hide', state !== 'out');
  $('#btnCloudLogout').classList.toggle('hide', state === 'out' || state === 'off');
  st.innerHTML = state === 'out'
    ? '尚未登入。請用公司 Google 帳號登入，才能取得共用的財產清冊並同步盤點結果。'
      + (typeof IS_IOS !== 'undefined' && IS_IOS && IS_STANDALONE ? '<br><b>iPhone 提醒：</b>若從主畫面圖示開啟的 App 無法完成登入，請改用 Safari 直接開啟網址登入，登入後再從主畫面開啟即可。' : '')
    : `${CLOUD ? `已登入：<b>${esc(CLOUD.name)}</b>（${esc(CLOUD.email)}）<br>` : ''}${esc(text || '')}`;
}
