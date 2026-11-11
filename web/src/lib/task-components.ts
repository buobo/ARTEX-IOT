import type { ComponentStatus } from "@/lib/types";

// 组件类型的中文名。与后端 db 层 type 白名单一致。
const COMPONENT_TYPE_LABELS: Record<string, string> = {
  web: "Web 服务",
  mqtt: "MQTT",
  ros: "ROS",
  ssh: "SSH",
  telnet: "Telnet",
  upnp: "UPnP",
  onvif: "ONVIF",
  rtsp: "RTSP",
  ftp: "FTP",
  other: "其它",
};

export const COMPONENT_STATUS_LABELS: Record<ComponentStatus, string> = {
  pending: "待挖",
  running: "挖掘中",
  completed: "已挖完",
  ignored: "不挖",
};

export const COMPONENT_STATUSES: ComponentStatus[] = ["pending", "running", "completed", "ignored"];

// 组件是怎么挂到任务上的（task_component_links.source）。
export const TASK_COMPONENT_SOURCE_LABELS: Record<string, string> = {
  agent: "Agent 登记",
  anchor: "黑板锚点",
  api: "组件 API",
  company: "企业关联",
  legacy: "历史关联",
  manual: "人工加入",
  system: "系统关联",
  task: "任务初始化",
};

export function componentSourceLabel(source: string): string {
  return TASK_COMPONENT_SOURCE_LABELS[source] ?? source;
}

export function componentTypeLabel(type: string): string {
  return COMPONENT_TYPE_LABELS[type] ?? type;
}

