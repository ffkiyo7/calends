// 常用服务目录的匹配规则（数据在 app/src/catalog/，网页联想与 MCP 共用）。
export interface ServiceEntry {
  name: string;
  aka: string[];
  cat: string;
  url: string;
  icon: string;
}

/** 比较时忽略大小写、全半角、空格和标点 */
const norm = (s: string) =>
  s
    .normalize('NFKC')
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, '');
const namesOf = (e: ServiceEntry) => [e.name, ...e.aka].map(norm).filter(Boolean);

/** 模糊搜索：完全一致 > 前缀 > 包含 */
export function searchServices<T extends ServiceEntry>(entries: T[], query: string, limit = 8): T[] {
  const k = norm(query);
  if (!k) return [];
  const score = (e: T) => {
    const names = namesOf(e);
    if (names.includes(k)) return 3;
    if (names.some((n) => n.startsWith(k))) return 2;
    return names.some((n) => n.includes(k) || (k.length >= 3 && n.length >= 3 && k.includes(n))) ? 1 : 0;
  };
  return entries
    .map((e) => ({ e, s: score(e) }))
    .filter((x) => x.s > 0)
    .sort((a, b) => b.s - a.s)
    .slice(0, limit)
    .map((x) => x.e);
}

/** 自动填充只认名称或别名完全一致，避免把相近的名字写成别家的图标和官网 */
export const exactServices = <T extends ServiceEntry>(entries: T[], name: string): T[] => {
  const k = norm(name);
  return k ? entries.filter((e) => namesOf(e).includes(k)) : [];
};
