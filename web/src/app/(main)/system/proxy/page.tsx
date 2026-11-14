"use client";

import * as React from "react";

import { LinkIcon, PlusIcon, RefreshCwIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import type { ProxyEntry, ProxySource, VLESSTransport } from "@/lib/types";

// 出口代理池管理页（阶段 1 + 1.5）。选路/粘性/封禁逻辑在后端 traffic/selector.go；
// vless 条目由后端内嵌 sing-box 引擎翻译成本地 socks 出口（server/egress_engine.go），
// 本页只做池与订阅源的 CRUD 和手动同步。池为空时出口回退到「系统配置」里的
// 全局代理（再退到直连），所以本页空着不影响现有行为。

const STATE_LABEL: Record<string, { label: string; variant: "default" | "secondary" | "destructive" | "outline" }> = {
  ok: { label: "可用", variant: "default" },
  banned: { label: "已封禁", variant: "destructive" },
  down: { label: "拨号失败", variant: "outline" },
};

const SOURCE_LABEL: Record<string, string> = {
  manual: "手动",
  subscription: "订阅",
};

function fmtTime(v: string | null): string {
  if (!v) return "—";
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString();
}

// vlessSummary 生成列表里 transport 摘要（TLS/WS/Reality…）。
function vlessSummary(t?: VLESSTransport): string {
  if (!t) return "";
  const parts: string[] = [t.security === "none" || !t.security ? "tcp" : (t.transport || "tcp")];
  if (t.security && t.security !== "none") parts.push(t.security);
  if (t.flow) parts.push(t.flow);
  return parts.join(" · ");
}

const emptyVless = (): VLESSTransport => ({ uuid: "", security: "tls", transport: "tcp" });

export default function ProxyPoolPage() {
  const [entries, setEntries] = React.useState<ProxyEntry[]>([]);
  const [sources, setSources] = React.useState<ProxySource[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [syncing, setSyncing] = React.useState<number | null>(null);

  // 手动添加表单
  const [scheme, setScheme] = React.useState("http");
  const [pastedURI, setPastedURI] = React.useState("");
  const [host, setHost] = React.useState("");
  const [port, setPort] = React.useState("");
  const [username, setUsername] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [name, setName] = React.useState("");
  const [saving, setSaving] = React.useState(false);
  const [vless, setVless] = React.useState<VLESSTransport>(emptyVless());

  // 订阅源表单
  const [srcName, setSrcName] = React.useState("");
  const [srcURL, setSrcURL] = React.useState("");
  const [srcSaving, setSrcSaving] = React.useState(false);

  const load = React.useCallback(() => {
    setLoading(true);
    Promise.all([api.proxyEntries(), api.proxySources()])
      .then(([e, s]) => {
        setEntries(e);
        setSources(s);
      })
      .catch((err) => toast.error("读取代理池失败：" + (err as Error).message))
      .finally(() => setLoading(false));
  }, []);
  React.useEffect(() => {
    load();
  }, [load]);

  function setV(patch: Partial<VLESSTransport>) {
    setVless((v) => ({ ...v, ...patch }));
  }

  async function addEntry() {
    setSaving(true);
    try {
      if (scheme === "vless" && pastedURI.trim()) {
        await api.createProxyEntry({ name: name.trim(), uri: pastedURI.trim() });
      } else if (scheme === "vless") {
        if (!host.trim() || !vless.uuid.trim()) {
          toast.error("vless 节点需要主机地址和 UUID");
          return;
        }
        await api.createProxyEntry({
          name: name.trim(),
          scheme: "vless",
          host: host.trim(),
          port: Number(port),
          transport: { ...vless },
        });
      } else {
        const p = Number(port);
        if (!host.trim() || !p) {
          toast.error("请填写主机地址和端口");
          return;
        }
        await api.createProxyEntry({
          name: name.trim(),
          scheme,
          host: host.trim(),
          port: p,
          username: username.trim(),
          password,
        });
      }
      toast.success("代理已加入池");
      setPastedURI("");
      setName("");
      setHost("");
      setPort("");
      setUsername("");
      setPassword("");
      setVless(emptyVless());
      load();
    } catch (err) {
      toast.error("添加失败：" + (err as Error).message);
    } finally {
      setSaving(false);
    }
  }

  async function toggleEntry(e: ProxyEntry) {
    try {
      await api.updateProxyEntry(e.id, { enabled: !e.enabled });
      load();
    } catch (err) {
      toast.error("更新失败：" + (err as Error).message);
    }
  }

  async function removeEntry(e: ProxyEntry) {
    try {
      await api.deleteProxyEntry(e.id);
      load();
    } catch (err) {
      toast.error("删除失败：" + (err as Error).message);
    }
  }

  async function addSource() {
    if (!srcName.trim() || !srcURL.trim()) {
      toast.error("请填写订阅名称和链接");
      return;
    }
    setSrcSaving(true);
    try {
      const src = await api.createProxySource({ name: srcName.trim(), url: srcURL.trim() });
      setSrcName("");
      setSrcURL("");
      await api.syncProxySource(src.id);
      toast.success("订阅源已添加并完成首次同步");
      load();
    } catch (err) {
      toast.error("添加失败：" + (err as Error).message);
    } finally {
      setSrcSaving(false);
    }
  }

  async function syncSource(src: ProxySource) {
    setSyncing(src.id);
    try {
      const r = await api.syncProxySource(src.id);
      toast.success(`同步完成：${r.count} 条`);
      load();
    } catch (err) {
      toast.error("同步失败：" + (err as Error).message);
      load();
    } finally {
      setSyncing(null);
    }
  }

  async function removeSource(src: ProxySource) {
    try {
      await api.deleteProxySource(src.id);
      load();
    } catch (err) {
      toast.error("删除失败：" + (err as Error).message);
    }
  }

  return (
    <div className="flex flex-col gap-6 p-6">
      <div>
        <h1 className="text-2xl font-semibold">出口代理池</h1>
        <p className="text-muted-foreground mt-1 text-sm">
          同一目标走同一出口（粘性）；命中封禁信号或拨号失败自动换下一条。vless 节点由内置 sing-box
          引擎接管，每节点一个独立出口。池为空时回退到系统配置里的全局代理，再退直连。
        </p>
      </div>

      <Tabs defaultValue="pool">
        <TabsList>
          <TabsTrigger value="pool">代理池（{entries.length}）</TabsTrigger>
          <TabsTrigger value="sources">订阅源（{sources.length}）</TabsTrigger>
        </TabsList>

        <TabsContent value="pool" className="flex flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">手动添加代理</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-3">
              <div className="grid grid-cols-2 gap-3 md:grid-cols-6">
                <div className="col-span-1">
                  <Label>协议</Label>
                  <Select value={scheme} onValueChange={setScheme}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="http">http</SelectItem>
                      <SelectItem value="https">https</SelectItem>
                      <SelectItem value="socks5">socks5</SelectItem>
                      <SelectItem value="vless">vless</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                {scheme === "vless" ? (
                  <div className="col-span-2 md:col-span-4">
                    <Label>粘贴分享链接（优先）</Label>
                    <Input
                      value={pastedURI}
                      onChange={(e) => setPastedURI(e.target.value)}
                      placeholder="vless://uuid@host:port?security=tls&type=ws&sni=…&path=/…"
                    />
                  </div>
                ) : (
                  <>
                    <div className="col-span-2">
                      <Label>主机</Label>
                      <Input value={host} onChange={(e) => setHost(e.target.value)} placeholder="proxy.example.com" />
                    </div>
                    <div className="col-span-1">
                      <Label>端口</Label>
                      <Input value={port} onChange={(e) => setPort(e.target.value)} placeholder="8080" inputMode="numeric" />
                    </div>
                    <div className="col-span-1">
                      <Label>用户名</Label>
                      <Input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="可选" />
                    </div>
                  </>
                )}
                <div className="col-span-1 md:col-span-1">
                  <Label>备注</Label>
                  <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="可选" />
                </div>
              </div>

              {scheme === "vless" && !pastedURI.trim() && (
                <div className="grid grid-cols-2 gap-3 md:grid-cols-6">
                  <div className="col-span-2">
                    <Label>UUID</Label>
                    <Input value={vless.uuid} onChange={(e) => setV({ uuid: e.target.value })} />
                  </div>
                  <div className="col-span-1">
                    <Label>加密层</Label>
                    <Select value={vless.security} onValueChange={(v) => setV({ security: v as VLESSTransport["security"] })}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="none">none</SelectItem>
                        <SelectItem value="tls">tls</SelectItem>
                        <SelectItem value="reality">reality</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="col-span-1">
                    <Label>传输层</Label>
                    <Select value={vless.transport} onValueChange={(v) => setV({ transport: v as VLESSTransport["transport"] })}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="tcp">tcp</SelectItem>
                        <SelectItem value="ws">ws</SelectItem>
                        <SelectItem value="grpc">grpc</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="col-span-1">
                    <Label>SNI</Label>
                    <Input value={vless.sni ?? ""} onChange={(e) => setV({ sni: e.target.value })} placeholder={vless.security === "tls" ? "可选" : "reality 必填"} />
                  </div>
                  <div className="col-span-1">
                    <Label>flow</Label>
                    <Input value={vless.flow ?? ""} onChange={(e) => setV({ flow: e.target.value })} placeholder="xtls-rprx-vision" />
                  </div>
                  {vless.transport === "ws" && (
                    <>
                      <div className="col-span-1">
                        <Label>WS Host</Label>
                        <Input value={vless.ws_host ?? ""} onChange={(e) => setV({ ws_host: e.target.value })} />
                      </div>
                      <div className="col-span-2">
                        <Label>WS Path</Label>
                        <Input value={vless.ws_path ?? ""} onChange={(e) => setV({ ws_path: e.target.value })} placeholder="/path" />
                      </div>
                    </>
                  )}
                  {vless.transport === "grpc" && (
                    <div className="col-span-2">
                      <Label>gRPC serviceName</Label>
                      <Input value={vless.grpc_service ?? ""} onChange={(e) => setV({ grpc_service: e.target.value })} />
                    </div>
                  )}
                  {vless.security === "reality" && (
                    <>
                      <div className="col-span-2">
                        <Label>Reality 公钥 (pbk)</Label>
                        <Input value={vless.reality_pbk ?? ""} onChange={(e) => setV({ reality_pbk: e.target.value })} />
                      </div>
                      <div className="col-span-1">
                        <Label>shortId (sid)</Label>
                        <Input value={vless.reality_sid ?? ""} onChange={(e) => setV({ reality_sid: e.target.value })} />
                      </div>
                    </>
                  )}
                </div>
              )}

              {scheme !== "vless" && (
                <div className="grid grid-cols-2 gap-3 md:grid-cols-6">
                  <div className="col-span-2 md:col-span-4">
                    <Label>密码</Label>
                    <Input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="可选" type="password" />
                  </div>
                </div>
              )}

              <Button onClick={addEntry} disabled={saving} className="w-fit">
                <PlusIcon /> {saving ? "添加中…" : "添加"}
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>地址</TableHead>
                    <TableHead>传输层</TableHead>
                    <TableHead>备注</TableHead>
                    <TableHead>来源</TableHead>
                    <TableHead>状态</TableHead>
                    <TableHead>最近使用</TableHead>
                    <TableHead>启用</TableHead>
                    <TableHead className="w-12" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {loading ? (
                    <TableRow>
                      <TableCell colSpan={8} className="text-muted-foreground text-center">
                        加载中…
                      </TableCell>
                    </TableRow>
                  ) : entries.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={8} className="text-muted-foreground text-center">
                        池为空——当前出口走全局代理/直连
                      </TableCell>
                    </TableRow>
                  ) : (
                    entries.map((e) => {
                      const st = STATE_LABEL[e.state] ?? { label: e.state, variant: "secondary" as const };
                      return (
                        <TableRow key={e.id}>
                          <TableCell className="font-mono text-sm">
                            {e.scheme === "vless"
                              ? `vless://${e.host}:${e.port}`
                              : `${e.scheme}://${e.host}:${e.port}${e.username ? ` (${e.username})` : ""}`}
                          </TableCell>
                          <TableCell>
                            {e.scheme === "vless" ? (
                              <Badge variant="secondary">{vlessSummary(e.transport)}</Badge>
                            ) : (
                              "—"
                            )}
                          </TableCell>
                          <TableCell className="text-sm">{e.name || "—"}</TableCell>
                          <TableCell>
                            <Badge variant={e.source === "subscription" ? "secondary" : "outline"}>
                              {SOURCE_LABEL[e.source] ?? e.source}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <Badge variant={st.variant}>{st.label}</Badge>
                            {e.last_error ? <span className="text-muted-foreground ml-2 text-xs">{e.last_error}</span> : null}
                          </TableCell>
                          <TableCell className="text-sm">{fmtTime(e.last_used_at)}</TableCell>
                          <TableCell>
                            <Switch checked={e.enabled} onCheckedChange={() => toggleEntry(e)} />
                          </TableCell>
                          <TableCell>
                            <Button variant="ghost" size="icon" onClick={() => removeEntry(e)} aria-label="删除">
                              <Trash2Icon />
                            </Button>
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="sources" className="flex flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">添加订阅源</CardTitle>
            </CardHeader>
            <CardContent className="grid grid-cols-1 gap-3 md:grid-cols-4">
              <div>
                <Label>名称</Label>
                <Input value={srcName} onChange={(e) => setSrcName(e.target.value)} placeholder="代理商 A" />
              </div>
              <div className="md:col-span-2">
                <Label>订阅链接</Label>
                <Input value={srcURL} onChange={(e) => setSrcURL(e.target.value)} placeholder="https://…" />
              </div>
              <div className="flex items-end">
                <Button onClick={addSource} disabled={srcSaving} className="w-full">
                  <LinkIcon /> {srcSaving ? "添加中…" : "添加并同步"}
                </Button>
              </div>
              <p className="text-muted-foreground text-xs md:col-span-4">
                格式：每行一个代理 URI（socks5://、http://、vless://…），响应可为 base64 整体编码。每 10 分钟自动同步。
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>名称</TableHead>
                    <TableHead>链接</TableHead>
                    <TableHead>最近同步</TableHead>
                    <TableHead>条目数</TableHead>
                    <TableHead>状态</TableHead>
                    <TableHead className="w-24" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sources.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6} className="text-muted-foreground text-center">
                        还没有订阅源
                      </TableCell>
                    </TableRow>
                  ) : (
                    sources.map((src) => (
                      <TableRow key={src.id}>
                        <TableCell className="text-sm">{src.name}</TableCell>
                        <TableCell className="max-w-64 truncate font-mono text-xs">{src.url}</TableCell>
                        <TableCell className="text-sm">{fmtTime(src.last_sync_at)}</TableCell>
                        <TableCell className="text-sm">{src.last_count}</TableCell>
                        <TableCell className="text-destructive text-xs">{src.last_error || "正常"}</TableCell>
                        <TableCell>
                          <div className="flex gap-1">
                            <Button variant="ghost" size="icon" onClick={() => syncSource(src)} disabled={syncing === src.id} aria-label="立即同步">
                              <RefreshCwIcon className={syncing === src.id ? "animate-spin" : ""} />
                            </Button>
                            <Button variant="ghost" size="icon" onClick={() => removeSource(src)} aria-label="删除">
                              <Trash2Icon />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
