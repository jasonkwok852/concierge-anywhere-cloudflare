// 使用CDN的模块化Firebase SDK
import { initializeApp } from 'https://www.gstatic.com/firebasejs/9.0.0/firebase-app.js';
import { getAuth } from 'https://www.gstatic.com/firebasejs/9.0.0/firebase-auth.js';

// 初始化函数
export async function initFirebase() {
  try {
    // 从Cloudflare Function获取配置
    const response = await fetch('/functions/firebase-config');
    if (!response.ok) throw new Error(`HTTP错误! 状态码: ${response.status}`);
    
    const firebaseConfig = await response.json();
    console.log('Firebase配置:', firebaseConfig);

    // 初始化Firebase
    const app = initializeApp(firebaseConfig);
    const auth = getAuth(app);
    
    console.log('Firebase初始化成功');
    return auth;
  } catch (error) {
    console.error('初始化失败:', error);
    throw new Error(`无法初始化Firebase: ${error.message}`);
  }
}

// 初始化Firebase UI（需在HTML中单独加载firebase-ui库）
export function initAuthUI(auth) {
  return new firebaseui.auth.AuthUI(auth);
}