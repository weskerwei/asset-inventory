// Firebase 專案設定。設為 null 時 App 以單機模式運作。
// 這些值本來就會出現在網頁中，不是密碼；資料安全由 Firebase 的「登入＋安全規則」保護：
// 只有以 @aetherai.com 公司帳號登入的人才能讀寫。
window.FIREBASE_CONFIG = {
  apiKey: "AIzaSyAgE-qAeu8AubUh4eEa57ObkF-1nhW7X-8",
  authDomain: "aetherai-asset-inventory.firebaseapp.com",
  projectId: "aetherai-asset-inventory",
  storageBucket: "aetherai-asset-inventory.firebasestorage.app",
  messagingSenderId: "508754987676",
  appId: "1:508754987676:web:b5ea93796067ca2ff33b59"
};
window.FIREBASE_ALLOWED_DOMAIN = 'aetherai.com';
