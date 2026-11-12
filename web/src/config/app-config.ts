import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "ARTEX-IOT",
  version: packageJson.version,
  copyright: `© ${currentYear}, ARTEX.`,
  // 站点 logo：换图后把 V 值加一，浏览器就不会继续用旧缓存。
  // logo 是完整标识（含 ARTEX-IOT 字标，用于登录/初始化页）；
  // logoMark 只有图形部分（侧边栏 40px 处用，字标在那种尺寸下不可读）。
  logo: "/logo.png?v=3",
  logoMark: "/logo-mark.png?v=3",
  meta: {
    title: "ARTEX — 自主渗透测试控制台",
    description: "LLM 驱动的自主渗透测试系统控制台",
  },
};
