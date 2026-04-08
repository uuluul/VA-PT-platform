"""
EASM Platform — FastAPI Backend
Nessus + Burp Suite Professional 整合
"""

import os, io, csv, time, threading
from datetime import datetime
from typing import Optional
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse
from pydantic import BaseModel, Field
import requests as req_lib

from tenable.nessus import Nessus

load_dotenv()

# ─── Nessus 設定 ──────────────────────────────────────

NESSUS_URL = f"https://{os.getenv('NESSUS_HOST', 'localhost')}:{os.getenv('NESSUS_PORT', '8834')}"
NESSUS_ACCESS_KEY = os.getenv("NESSUS_ACCESS_KEY", "")
NESSUS_SECRET_KEY = os.getenv("NESSUS_SECRET_KEY", "")
NESSUS_USERNAME = os.getenv("NESSUS_USERNAME", "")
NESSUS_PASSWORD = os.getenv("NESSUS_PASSWORD", "")

# ─── Burp Suite 設定 ──────────────────────────────────

BURP_URL = os.getenv("BURP_URL", "http://192.168.30.137:1337")
BURP_API_KEY = os.getenv("BURP_API_KEY", "")

scan_tracker: dict = {}
burp_tracker: dict = {}
nessus: Optional[Nessus] = None


def get_nessus() -> Nessus:
    global nessus
    if nessus is None:
        try:
            if NESSUS_ACCESS_KEY and NESSUS_SECRET_KEY:
                nessus = Nessus(
                    url=NESSUS_URL,
                    access_key=NESSUS_ACCESS_KEY,
                    secret_key=NESSUS_SECRET_KEY,
                )
            elif NESSUS_USERNAME and NESSUS_PASSWORD:
                nessus = Nessus(
                    url=NESSUS_URL,
                    username=NESSUS_USERNAME,
                    password=NESSUS_PASSWORD,
                )
            else:
                raise ValueError("請在 .env 設定 Nessus 帳密或 API Keys")
        except Exception as e:
            raise HTTPException(502, f"無法連線 Nessus: {e}")
    return nessus


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        n = get_nessus()
        info = n.server.properties()
        print(f"✓ Nessus connected: {info.get('server_version', 'unknown')} @ {NESSUS_URL}")
    except Exception as e:
        print(f"✗ Nessus: {e}")
    yield


app = FastAPI(title="EASM Platform", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# ─── Request Model ─────────────────────────────────────

class ScanRequest(BaseModel):
    name: str = Field(..., examples=["Weekly EASM Scan"])
    targets: str = Field(..., examples=["192.168.1.0/24, 10.0.0.1"])
    port_range: Optional[str] = Field(None, examples=["1-1024, 3389"])
    template_name: Optional[str] = Field(None, examples=["basic"])
    policy_id: Optional[int] = None
    description: Optional[str] = ""


# ─── Health & Server Info ──────────────────────────────

@app.get("/api/health")
async def health():
    try:
        n = get_nessus()
        info = n.server.properties()
        return {
            "status": "ok",
            "nessus_connected": True,
            "nessus_version": info.get("server_version"),
            "nessus_build": info.get("server_build"),
            "loaded_plugins": info.get("loaded_plugin_set"),
        }
    except:
        return {"status": "ok", "nessus_connected": False}


@app.get("/api/server")
async def server_info():
    """Nessus 伺服器完整資訊"""
    n = get_nessus()
    props = n.server.properties()
    status = n.server.status()
    return {"properties": props, "status": status}


# ─── Templates / Policies / Folders / Scanners ─────────

@app.get("/api/templates")
async def templates():
    """列出所有掃描模板"""
    n = get_nessus()
    tmpl = n.editor.template_list("scan")
    return {"templates": [
        {"uuid": t.get("uuid"), "name": t.get("name"), "title": t.get("title", t.get("name"))}
        for t in tmpl
    ]}


@app.get("/api/policies")
async def policies():
    """列出所有掃描策略"""
    n = get_nessus()
    try:
        pols = n.policies.list()
        pol_list = pols.get("policies", []) if isinstance(pols, dict) else pols
        if not pol_list:
            return {"policies": []}
        return {"policies": [
            {"id": p.get("id"), "name": p.get("name"), "description": p.get("description", "")}
            for p in pol_list
        ]}
    except Exception:
        return {"policies": []}


@app.get("/api/policies/{policy_id}")
async def policy_detail(policy_id: int):
    """取得策略詳情（含所有設定）"""
    n = get_nessus()
    return n.policies.details(policy_id)


class PolicyCreateRequest(BaseModel):
    name: str = Field(..., examples=["Web Server Policy"])
    description: Optional[str] = ""
    template_name: Optional[str] = Field("advanced", examples=["advanced"])
    # Discovery
    port_range: Optional[str] = Field("default", examples=["1-1024,3389,8080-8443"])
    ping_method: Optional[str] = Field("ARP, TCP, and ICMP", examples=["ARP, TCP, and ICMP"])
    # Credentials (SSH)
    ssh_username: Optional[str] = None
    ssh_password: Optional[str] = None
    ssh_port: Optional[int] = Field(22)
    # Credentials (SMB / Windows)
    smb_username: Optional[str] = None
    smb_password: Optional[str] = None
    smb_domain: Optional[str] = None
    # Credentials (SNMP)
    snmp_community: Optional[str] = None
    # Plugin families to enable (空 = 全部啟用)
    enabled_families: Optional[list[str]] = Field(
        None,
        examples=[["Port scanners", "Web Servers", "Databases", "General"]],
        description="要啟用的 Plugin 家族名稱，留空 = 全部啟用",
    )
    # Assessment
    scan_web_apps: Optional[bool] = Field(False, description="是否掃描 Web 應用程式")


@app.post("/api/policies")
async def create_policy(req: PolicyCreateRequest):
    """
    建立自訂掃描策略（簡化版）
    把複雜的 Nessus Policy 設定簡化成幾個常用參數
    """
    n = get_nessus()

    # 1. 找 template uuid
    tmpl_uuid = None
    for t in n.editor.template_list("scan"):
        if (req.template_name or "advanced").lower() in (t.get("name") or "").lower():
            tmpl_uuid = t["uuid"]
            break
    if not tmpl_uuid:
        for t in n.editor.template_list("scan"):
            if "advanced" in (t.get("name") or "").lower():
                tmpl_uuid = t["uuid"]
                break

    # 2. 建立 Policy payload
    settings = {
        "name": req.name,
        "description": req.description or "",
    }

    # Discovery - Port range
    if req.port_range:
        settings["portscan_range"] = req.port_range

    # 3. Credentials
    credentials = {"add": {}}

    if req.ssh_username:
        credentials["add"]["Host"] = {"SSH": [{
            "auth_method": "password",
            "username": req.ssh_username,
            "password": req.ssh_password or "",
            "port": req.ssh_port or 22,
        }]}

    if req.smb_username:
        smb = credentials["add"].setdefault("Host", {})
        smb["Windows"] = [{
            "auth_method": "Password",
            "username": req.smb_username,
            "password": req.smb_password or "",
            "domain": req.smb_domain or "",
        }]

    if req.snmp_community:
        snmp = credentials["add"].setdefault("Host", {})
        snmp["SNMP"] = [{
            "community": req.snmp_community,
            "security_level": "noAuthNoPriv",
        }]

    # 4. 建立 policy 的完整 payload
    payload = {
        "uuid": tmpl_uuid,
        "settings": settings,
    }
    if credentials["add"]:
        payload["credentials"] = credentials

    # 5. Plugin families（如果有指定）
    if req.enabled_families:
        # 先拿所有 families
        all_families = n.plugins.families()
        family_list = all_families.get("families", []) if isinstance(all_families, dict) else all_families

        plugins = {"family": {}}
        for fam in family_list:
            fam_name = fam.get("name", "")
            fam_id = str(fam.get("id", ""))
            if any(ef.lower() in fam_name.lower() for ef in req.enabled_families):
                plugins["family"][fam_id] = {"status": "enabled"}
            else:
                plugins["family"][fam_id] = {"status": "disabled"}
        payload["plugins"] = plugins

    try:
        # pyTenable: policies 底層就是 POST /policies
        result = n._post("policies", json=payload)
        return {
            "message": "Policy 建立成功",
            "policy_id": result.get("policy_id"),
            "policy_name": req.name,
        }
    except Exception as e:
        raise HTTPException(500, f"建立 Policy 失敗: {e}")


@app.put("/api/policies/{policy_id}")
async def update_policy(policy_id: int, req: PolicyCreateRequest):
    """更新已有的 Policy"""
    n = get_nessus()
    settings = {"name": req.name, "description": req.description or ""}
    if req.port_range:
        settings["portscan_range"] = req.port_range

    payload = {"settings": settings}

    # Credentials
    credentials = {"add": {}}
    if req.ssh_username:
        credentials["add"]["Host"] = {"SSH": [{
            "auth_method": "password",
            "username": req.ssh_username,
            "password": req.ssh_password or "",
            "port": req.ssh_port or 22,
        }]}
    if req.smb_username:
        smb = credentials["add"].setdefault("Host", {})
        smb["Windows"] = [{
            "auth_method": "Password",
            "username": req.smb_username,
            "password": req.smb_password or "",
            "domain": req.smb_domain or "",
        }]
    if req.snmp_community:
        snmp = credentials["add"].setdefault("Host", {})
        snmp["SNMP"] = [{"community": req.snmp_community, "security_level": "noAuthNoPriv"}]
    if credentials["add"]:
        payload["credentials"] = credentials

    try:
        n._put(f"policies/{policy_id}", json=payload)
        return {"message": "Policy 更新成功", "policy_id": policy_id}
    except Exception as e:
        raise HTTPException(500, f"更新失敗: {e}")


@app.delete("/api/policies/{policy_id}")
async def delete_policy(policy_id: int):
    """刪除 Policy"""
    n = get_nessus()
    try:
        n._delete(f"policies/{policy_id}")
        return {"message": "deleted"}
    except Exception as e:
        raise HTTPException(500, f"刪除失敗: {e}")


@app.get("/api/folders")
async def folders():
    """列出資料夾"""
    n = get_nessus()
    fols = n.folders.list()
    return {"folders": [
        {"id": f.get("id"), "name": f.get("name"), "type": f.get("type")}
        for f in fols
    ]}


@app.post("/api/folders")
async def create_folder(name: str):
    """建立資料夾"""
    n = get_nessus()
    return n.folders.create(name)


@app.get("/api/scanners")
async def scanners():
    """列出可用的 Scanner"""
    n = get_nessus()
    return {"scanners": n.scanners.list()}


# ─── Plugin 資訊 ──────────────────────────────────────

@app.get("/api/plugins/families")
async def plugin_families():
    """列出所有 Plugin 家族"""
    n = get_nessus()
    return n.plugins.families()


@app.get("/api/plugins/families/{family_id}")
async def plugin_family_detail(family_id: int):
    """列出特定家族的所有 Plugin"""
    n = get_nessus()
    return n.plugins.family_details(family_id)


@app.get("/api/plugins/{plugin_id}")
async def plugin_detail(plugin_id: int):
    """取得單一 Plugin 詳情"""
    n = get_nessus()
    return n.plugins.plugin_details(plugin_id)


# ─── 掃描管理 ─────────────────────────────────────────

@app.post("/api/scans")
async def create_scan(req: ScanRequest, bg: BackgroundTasks):
    """建立掃描 + 自動啟動"""
    n = get_nessus()

    # 找 template uuid
    tmpl_uuid = None
    if req.template_name:
        for t in n.editor.template_list("scan"):
            if req.template_name.lower() in (t.get("name") or "").lower():
                tmpl_uuid = t["uuid"]
                break
    if not tmpl_uuid:
        # 預設用 basic network scan
        for t in n.editor.template_list("scan"):
            if "basic" in (t.get("name") or "").lower():
                tmpl_uuid = t["uuid"]
                break

    desc = req.description or ""
    if req.port_range:
        desc += f" [Ports: {req.port_range}]"

    # 組 settings
    settings = {
        "name": req.name,
        "description": desc,
        "text_targets": req.targets,
        "enabled": True,
        "launch": "ON_DEMAND",
    }
    if req.policy_id:
        settings["policy_id"] = req.policy_id

    try:
        # pyTenable: scans.create() 接受 uuid + settings dict
        result = n.scans.create(uuid=tmpl_uuid, settings=settings)
        sid = result.get("scan", {}).get("id")
        if not sid:
            raise HTTPException(500, "建立失敗：未取得 scan_id")

        # 啟動
        scan_uuid = n.scans.launch(sid)

        scan_tracker[sid] = {
            "name": req.name, "targets": req.targets,
            "status": "running", "scan_uuid": scan_uuid,
            "created_at": datetime.utcnow().isoformat(),
        }
        bg.add_task(_poll, sid)

        return {"scan_id": sid, "scan_uuid": scan_uuid, "status": "launched"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"掃描失敗: {e}")


# ─── 批次掃描（CSV 上傳）─────────────────────────────

@app.get("/api/batch/template")
async def batch_template():
    """下載批次掃描 CSV 範本"""
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["name", "targets", "policy_id", "port_range", "template_name", "description"])
    w.writerow(["Web Servers Scan", "192.168.1.10, 192.168.1.11", "", "80,443,8080,8443", "basic", "Web server group"])
    w.writerow(["DB Servers Scan", "10.0.0.50, 10.0.0.51", "21", "1433,3306,5432,27017", "", "Database servers"])
    w.writerow(["Office Network", "172.16.0.0/24", "", "", "basic", "Office full scan"])
    out.seek(0)
    return StreamingResponse(
        io.BytesIO(out.getvalue().encode("utf-8-sig")),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="batch_scan_template.csv"'},
    )


@app.post("/api/batch/scans")
async def batch_create_scans(bg: BackgroundTasks, file: UploadFile = File(...)):
    """
    上傳 CSV 批次建立掃描
    CSV 欄位: name, targets, policy_id, port_range, template_name, description
    系統會依 policy_id 自動分組，同一 policy 的 targets 合併成一次掃描
    """
    content = await file.read()
    text = content.decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(text))

    # 解析每一行
    rows = []
    for i, row in enumerate(reader):
        name = (row.get("name") or "").strip()
        targets = (row.get("targets") or "").strip()
        if not targets:
            continue
        rows.append({
            "name": name or f"Batch Scan {i+1}",
            "targets": targets,
            "policy_id": int(row["policy_id"]) if row.get("policy_id", "").strip() else None,
            "port_range": (row.get("port_range") or "").strip() or None,
            "template_name": (row.get("template_name") or "").strip() or None,
            "description": (row.get("description") or "").strip() or "",
        })

    if not rows:
        raise HTTPException(400, "CSV 中沒有有效的掃描目標")

    n = get_nessus()

    # 快取 template 清單（避免每次都查）
    tmpl_list = n.editor.template_list("scan")
    def find_uuid(name_hint):
        if name_hint:
            for t in tmpl_list:
                if name_hint.lower() in (t.get("name") or "").lower():
                    return t["uuid"]
        for t in tmpl_list:
            if "basic" in (t.get("name") or "").lower():
                return t["uuid"]
        return tmpl_list[0]["uuid"] if tmpl_list else None

    results = []
    for row in rows:
        try:
            tmpl_uuid = find_uuid(row["template_name"])
            desc = row["description"]
            if row["port_range"]:
                desc += f" [Ports: {row['port_range']}]"

            settings = {
                "name": row["name"],
                "description": desc,
                "text_targets": row["targets"],
                "enabled": True,
                "launch": "ON_DEMAND",
            }
            if row["policy_id"]:
                settings["policy_id"] = row["policy_id"]

            result = n.scans.create(uuid=tmpl_uuid, settings=settings)
            sid = result.get("scan", {}).get("id")

            if sid:
                scan_uuid = n.scans.launch(sid)
                scan_tracker[sid] = {
                    "name": row["name"], "targets": row["targets"],
                    "status": "running", "scan_uuid": scan_uuid,
                    "created_at": datetime.utcnow().isoformat(),
                }
                bg.add_task(_poll, sid)
                results.append({"scan_id": sid, "name": row["name"],
                                "targets": row["targets"], "status": "launched"})
            else:
                results.append({"scan_id": None, "name": row["name"],
                                "targets": row["targets"], "status": "failed: no scan_id"})
        except Exception as e:
            results.append({"scan_id": None, "name": row["name"],
                            "targets": row["targets"], "status": f"failed: {e}"})

    launched = sum(1 for r in results if r["status"] == "launched")
    return {
        "total": len(results),
        "launched": launched,
        "failed": len(results) - launched,
        "scans": results,
    }


@app.get("/api/scans")
async def list_scans():
    """列出所有掃描"""
    n = get_nessus()
    data = n.scans.list()
    scans = data.get("scans", []) if isinstance(data, dict) else data
    return {"scans": [
        {
            "id": s.get("id"), "name": s.get("name"), "status": s.get("status"),
            "folder_id": s.get("folder_id"),
            "last_modification_date": s.get("last_modification_date"),
        }
        for s in (scans or [])
    ]}


@app.get("/api/scans/{sid}")
async def scan_detail(sid: int):
    """掃描完整原始資料"""
    n = get_nessus()
    return n.scans.details(sid)


@app.get("/api/scans/{sid}/status")
async def scan_status(sid: int):
    """掃描狀態"""
    n = get_nessus()
    detail = n.scans.details(sid)
    status = detail.get("info", {}).get("status", "unknown")
    return {"scan_id": sid, "status": status, **(scan_tracker.get(sid, {}))}


@app.post("/api/scans/{sid}/launch")
async def launch_scan(sid: int, bg: BackgroundTasks):
    """啟動（或重新啟動）掃描"""
    n = get_nessus()
    uuid = n.scans.launch(sid)
    bg.add_task(_poll, sid)
    return {"scan_uuid": uuid, "status": "launched"}


@app.post("/api/scans/{sid}/pause")
async def pause_scan(sid: int):
    n = get_nessus()
    n.scans.pause(sid)
    return {"message": "paused"}


@app.post("/api/scans/{sid}/resume")
async def resume_scan(sid: int):
    n = get_nessus()
    n.scans.resume(sid)
    return {"message": "resumed"}


@app.post("/api/scans/{sid}/stop")
async def stop_scan(sid: int):
    n = get_nessus()
    n.scans.stop(sid)
    return {"message": "stopped"}


@app.post("/api/scans/{sid}/kill")
async def kill_scan(sid: int):
    """強制終止掃描"""
    n = get_nessus()
    n.scans.kill(sid)
    return {"message": "killed"}


@app.delete("/api/scans/{sid}")
async def delete_scan(sid: int):
    n = get_nessus()
    n.scans.delete(sid)
    scan_tracker.pop(sid, None)
    return {"message": "deleted"}


@app.post("/api/scans/{sid}/copy")
async def copy_scan(sid: int, name: Optional[str] = None):
    """複製掃描"""
    n = get_nessus()
    return n.scans.copy(sid, name=name)


# ─── 掃描結果 ─────────────────────────────────────────

@app.get("/api/scans/{sid}/results")
async def scan_results(sid: int):
    """結構化結果（Dashboard 用）"""
    n = get_nessus()
    detail = n.scans.details(sid)

    info = detail.get("info", {})
    hosts = detail.get("hosts", [])
    vulns = detail.get("vulnerabilities", [])

    sev_map = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
    sev_summary = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    for v in vulns:
        lbl = sev_map.get(v.get("severity", 0), "info")
        sev_summary[lbl] += v.get("count", 1)

    return {
        "scan_info": {
            "name": info.get("name"),
            "status": info.get("status"),
            "targets": info.get("targets"),
            "start_time": info.get("scan_start"),
            "end_time": info.get("scan_end"),
            "host_count": info.get("hostcount", 0),
            "policy": info.get("policy"),
            "scanner_name": info.get("scanner_name"),
        },
        "hosts": [
            {
                "host_id": h.get("host_id"),
                "hostname": h.get("hostname"),
                "severity_counts": {
                    "critical": h.get("critical", 0),
                    "high": h.get("high", 0),
                    "medium": h.get("medium", 0),
                    "low": h.get("low", 0),
                    "info": h.get("info", 0),
                },
                "score": h.get("score", 0),
            }
            for h in hosts
        ],
        "vulnerabilities": sorted(
            [
                {
                    "plugin_id": v.get("plugin_id"),
                    "plugin_name": v.get("plugin_name"),
                    "plugin_family": v.get("plugin_family", ""),
                    "severity": v.get("severity", 0),
                    "severity_label": sev_map.get(v.get("severity", 0), "info"),
                    "count": v.get("count", 0),
                    "vpr_score": v.get("vpr_score"),
                }
                for v in vulns
            ],
            key=lambda x: x["severity"],
            reverse=True,
        ),
        "severity_summary": sev_summary,
    }


@app.get("/api/scans/{sid}/hosts/{hid}")
async def host_vulns(sid: int, hid: int):
    """特定主機的弱點"""
    n = get_nessus()
    return n.scans.host_details(sid, hid)


@app.get("/api/scans/{sid}/hosts/{hid}/plugins/{pid}")
async def plugin_output(sid: int, hid: int, pid: int):
    """特定弱點的詳細輸出"""
    n = get_nessus()
    return n.scans.plugin_output(sid, hid, pid)


# ─── 匯出報告 ─────────────────────────────────────────

@app.get("/api/scans/{sid}/export/csv")
async def export_csv(sid: int):
    """從結構化資料匯出 CSV"""
    n = get_nessus()
    detail = n.scans.details(sid)
    vulns = detail.get("vulnerabilities", [])
    sev_map = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}

    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["Plugin ID", "Name", "Severity", "Count", "Family"])
    for v in sorted(vulns, key=lambda x: x.get("severity", 0), reverse=True):
        w.writerow([
            v.get("plugin_id"), v.get("plugin_name"),
            sev_map.get(v.get("severity", 0), "info"),
            v.get("count", 0), v.get("plugin_family", ""),
        ])
    out.seek(0)
    return StreamingResponse(
        io.BytesIO(out.getvalue().encode("utf-8-sig")),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="scan_{sid}.csv"'},
    )


@app.get("/api/scans/{sid}/export/nessus")
async def export_nessus(sid: int, format: str = "nessus"):
    """
    從 Nessus 匯出原始報告
    format: nessus / csv / html / db
    """
    n = get_nessus()
    fobj = io.BytesIO()
    n.scans.export_scan(sid, fobj=fobj, format=format)
    fobj.seek(0)

    ext = {"nessus": "nessus", "csv": "csv", "html": "html", "db": "db"}.get(format, "nessus")
    media = {"csv": "text/csv", "html": "text/html"}.get(format, "application/octet-stream")

    return StreamingResponse(
        fobj, media_type=media,
        headers={"Content-Disposition": f'attachment; filename="nessus_{sid}.{ext}"'},
    )


# ─── Scan History ─────────────────────────────────────

@app.get("/api/scans/{sid}/history")
async def scan_history(sid: int):
    """掃描歷史紀錄"""
    n = get_nessus()
    detail = n.scans.details(sid)
    return {"history": detail.get("history", [])}


# ─── 背景輪詢 ─────────────────────────────────────────

def _poll(sid: int):
    n = get_nessus()
    try:
        for _ in range(480):  # 最多 2 小時 (480 x 15s)
            detail = n.scans.details(sid)
            status = detail.get("info", {}).get("status", "unknown")
            if sid in scan_tracker:
                scan_tracker[sid]["status"] = status
            if status in ("completed", "canceled", "aborted"):
                if sid in scan_tracker:
                    scan_tracker[sid]["completed_at"] = datetime.utcnow().isoformat()
                break
            time.sleep(15)
    except Exception:
        if sid in scan_tracker:
            scan_tracker[sid]["status"] = "error"


# ═══════════════════════════════════════════════════════
# BURP SUITE PROFESSIONAL API
# ═══════════════════════════════════════════════════════

def burp_api(method, path, json_data=None):
    if BURP_API_KEY:
        url = f"{BURP_URL}/{BURP_API_KEY}/v0.1{path}"  # key 在 v0.1 前面
    else:
        url = f"{BURP_URL}/v0.1{path}"
    headers = {"Content-Type": "application/json"}
    try:
        r = req_lib.request(method, url, headers=headers, json=json_data, timeout=30)
        print(f"[DEBUG] burp_api {method} {url} -> {r.status_code} {r.text[:300]}")
        r.raise_for_status()
        if r.content:
            return r.json()
        return {}
    except req_lib.exceptions.ConnectionError:
        raise HTTPException(502, "無法連線 Burp Suite，請確認 REST API 已啟用")
    except Exception as e:
        raise HTTPException(500, f"Burp API 錯誤: {e}")


@app.get("/api/burp/health")
async def burp_health():
    try:
        if BURP_API_KEY:
            url = f"{BURP_URL}/{BURP_API_KEY}/v0.1/knowledge_base/issue_definitions"
        else:
            url = f"{BURP_URL}/v0.1/knowledge_base/issue_definitions"

        r = req_lib.get(url, timeout=10)
        # 200 或 404 都代表 Burp 有回應，就是連線成功
        if r.status_code in (200, 404):
            return {"status": "ok", "burp_connected": True}
        return {"status": "ok", "burp_connected": False}
    except Exception as e:
        print(f"[DEBUG] Burp error: {e}")
        return {"status": "ok", "burp_connected": False}

@app.get("/api/burp/scans/list")
async def burp_list_scans():
    """列出所有 Burp 掃描記錄"""
    scans = [
        {"task_id": k, **v}
        for k, v in burp_tracker.items()
    ]
    return {"scans": scans}

# ─── Burp 掃描管理 ────────────────────────────────────

class BurpScanRequest(BaseModel):
    urls: list[str] = Field(..., examples=[["https://example.com"]])
    name: Optional[str] = Field(None, examples=["Web App Scan"])
    preset: Optional[str] = Field("standard", examples=["quick", "standard", "deep", "custom"])

    # 自訂模式（Scan Config 頁面的設定）
    scan_type: Optional[str] = Field("crawl_and_audit")   # crawl_and_audit / crawl / api_only
    protocol: Optional[str] = Field("httpAndHttps")     # http_and_https / specified
    scan_mode: Optional[str] = Field(None)                # Burp 官方 preset 名稱，自訂時用
    isolated: Optional[bool] = Field(False)

    # URL Scope
    scope_include: Optional[list[str]] = None
    scope_exclude: Optional[list[str]] = None

    # Application Login
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None

    # Resource Pool（自訂時用）
    resource_pool: Optional[dict] = None
 
 
# Preset 對應的 Named Configurations
BURP_PRESETS = {
    "quick": [
        "Crawl strategy - fastest",
        "Audit checks - extensions only",
    ],
    "standard": [
        "Crawl strategy - fast",
        "Audit checks - all without JavaScript analysis",
    ],
    "deep": [
        "Crawl strategy - most complete",
        "Audit checks - all",
        "Audit coverage - thorough",
    ],
}
 
CRAWL_STRATEGY_MAP = {
    "fastest":      "Crawl strategy - fastest",
    "fast":         "Crawl strategy - fast",
    "complete":     "Crawl strategy - most complete",
    "more_complete":"Crawl strategy - more complete",
}
 
AUDIT_MODE_MAP = {
    "extensions_only":  "Audit checks - extensions only",
    "all_without_js":   "Audit checks - all without JavaScript analysis",
    "all":              "Audit checks - all",
}
 
AUDIT_COVERAGE_MAP = {
    "thorough":  "Audit coverage - thorough",
    "maximize":  "Audit coverage - maximize",
}
 
INSERTION_POINT_MAP = {
    "forms_url":        "Audit insertion points - forms and URL parameters only",
    "forms_url_cookie": "Audit insertion points - forms, URL and cookie parameters",
    "all":              "Audit insertion points - all except URL parameters",
}
 

@app.post("/api/burp/scans")
async def burp_create_scan(req: BurpScanRequest, bg: BackgroundTasks):
    try:
        configs = []

        if req.preset and req.preset != "custom":
            # Quick / Standard / Deep — 不帶 scan_configurations（避免 Unknown config 錯誤）
            pass
        else:
            # 自訂模式 — 直接用 scan_mode 帶 Burp 官方名稱
            if req.scan_mode:
                configs.append({"type": "NamedConfiguration", "name": req.scan_mode})

        payload = {"urls": req.urls}

        if configs:
            payload["scan_configurations"] = configs

        # Scope
        scope = {}
        if req.scope_include:
            scope["include"] = [{"rule": u, "type": "SimpleScopeDef"} for u in req.scope_include]
        if req.scope_exclude:
            scope["exclude"] = [{"rule": u, "type": "SimpleScopeDef"} for u in req.scope_exclude]
        if scope:
            payload["scope"] = scope

        # Application logins
        if req.username and req.password:
            login = {"username": req.username, "password": req.password}
            if req.login_url:
                login["login_url"] = req.login_url
            payload["application_logins"] = [login]

        print(f"[DEBUG] Burp scan payload: {payload}")

        url = f"{BURP_URL}/v0.1/scan"
        headers = {"Content-Type": "application/json"}

        if BURP_API_KEY:
            url = f"{BURP_URL}/{BURP_API_KEY}/v0.1/scan"  # key 在 v0.1 前面
        else:
            url = f"{BURP_URL}/v0.1/scan"
        if BURP_API_KEY:
            url = f"{BURP_URL}/v0.1/{BURP_API_KEY}/scan"

        r = req_lib.post(url, headers=headers, json=payload, timeout=30)
        print(f"[DEBUG] Burp response: {r.status_code} body={r.text[:300]}")

        location = r.headers.get("Location", "")
        task_id = location.rstrip("/").split("/")[-1] if location else None

        if not task_id or task_id == "scan":
            raise HTTPException(500, f"無法取得 Task ID，Burp 回傳: {r.status_code}")

        burp_tracker[task_id] = {
            "name": req.name or ", ".join(req.urls),
            "urls": req.urls,
            "status": "running",
            "engine": "burp",
            "preset": req.preset or "custom",
            "created_at": datetime.utcnow().isoformat(),
        }
        bg.add_task(_poll_burp, task_id)

        return {"task_id": task_id, "status": "launched", "engine": "burp", "preset": req.preset}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Burp 掃描失敗: {e}")


@app.get("/api/burp/scans/{task_id}")
async def burp_scan_status(task_id: str):
    """取得 Burp 掃描狀態與進度"""
    try:
        data = burp_api("GET", f"/scan/{task_id}")
        tracker = burp_tracker.get(task_id, {})
        return {
            "task_id": task_id,
            "status": data.get("scan_status"),
            "scan_metrics": data.get("scan_metrics"),
            "issues": data.get("issue_events", []),
            **tracker,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"取得狀態失敗: {e}")


@app.get("/api/burp/scans/{task_id}/results")
async def burp_scan_results(task_id: str):
    """取得 Burp 掃描結果（結構化，Dashboard 用）"""
    try:
        data = burp_api("GET", f"/scan/{task_id}")

        issues = data.get("issue_events", [])
        sev_map = {"high": "high", "medium": "medium", "low": "low", "info": "info", "information": "info"}
        sev_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        vuln_list = []
        for issue in issues:
            detail = issue.get("issue", {})
            sev = sev_map.get(detail.get("severity", "").lower(), "info")
            sev_summary[sev] += 1
            vuln_list.append({
                "name": detail.get("name", ""),
                "severity": sev,
                "confidence": detail.get("confidence", ""),
                "path": detail.get("path", ""),
                "origin": detail.get("origin", ""),
                "type_index": detail.get("type_index", ""),
                "description": detail.get("description", ""),
                "remediation": detail.get("remediation", ""),
            })

        # 按嚴重度排序
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        vuln_list.sort(key=lambda x: sev_order.get(x["severity"], 0), reverse=True)

        tracker = burp_tracker.get(task_id, {})
        return {
            "scan_info": {
                "name": tracker.get("name", f"Burp Scan {task_id}"),
                "status": data.get("scan_status", "unknown"),
                "engine": "burp",
                "urls": tracker.get("urls", []),
                "metrics": data.get("scan_metrics"),
            },
            "vulnerabilities": vuln_list,
            "severity_summary": sev_summary,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"取得結果失敗: {e}")


@app.get("/api/burp/scans/{task_id}/export/html")
async def burp_export_html(task_id: str):
    try:
        if BURP_API_KEY:
            url = f"{BURP_URL}/v0.1/{BURP_API_KEY}/scan/{task_id}/report?reportType=HTML"
        else:
            url = f"{BURP_URL}/v0.1/scan/{task_id}/report?reportType=HTML"
        r = req_lib.get(url, timeout=60)
        r.raise_for_status()
        return StreamingResponse(
            io.BytesIO(r.content),
            media_type="text/html",
            headers={"Content-Disposition": f'attachment; filename="burp_scan_{task_id}.html"'},
        )
    except Exception as e:
        raise HTTPException(500, f"匯出失敗: {e}")


@app.get("/api/burp/scans/{task_id}/export/xml")
async def burp_export_xml(task_id: str):
    try:
        if BURP_API_KEY:
            url = f"{BURP_URL}/v0.1/{BURP_API_KEY}/scan/{task_id}/report?reportType=XML"
        else:
            url = f"{BURP_URL}/v0.1/scan/{task_id}/report?reportType=XML"
        r = req_lib.get(url, timeout=60)
        r.raise_for_status()
        return StreamingResponse(
            io.BytesIO(r.content),
            media_type="application/xml",
            headers={"Content-Disposition": f'attachment; filename="burp_scan_{task_id}.xml"'},
        )
    except Exception as e:
        raise HTTPException(500, f"匯出失敗: {e}")


# ─── Burp 背景輪詢 ────────────────────────────────────

def _poll_burp(task_id: str):
    try:
        for _ in range(720):  # 最多 3 小時
            data = burp_api("GET", f"/scan/{task_id}")
            status = data.get("scan_status", "unknown")
            if task_id in burp_tracker:
                burp_tracker[task_id]["status"] = status
                metrics = data.get("scan_metrics", {})
                if metrics:
                    burp_tracker[task_id]["progress"] = metrics.get("crawl_and_audit_progress", 0)
            if status in ("succeeded", "failed", "cancelled"):
                if task_id in burp_tracker:
                    burp_tracker[task_id]["completed_at"] = datetime.utcnow().isoformat()
                break
            time.sleep(15)
    except Exception:
        if task_id in burp_tracker:
            burp_tracker[task_id]["status"] = "error"


# ─── 首頁（serve Dashboard）────────────────────────────

@app.get("/")
async def root():
    return FileResponse("index.html")


# ─── 啟動 ─────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)