# netscaler.py
"""NetScaler 14.x NITRO client helpers.

Features:
- login/logout
- create/delete/update LB vServer
- create servicegroup, add/remove members
- bind monitor to servicegroup (servicegroup_lbmonitor_binding)
- bind SSL cert to vServer
- inventory helpers
- idempotent operations & error handling
"""

import requests
import logging
from typing import List, Dict, Optional
from requests.exceptions import ConnectTimeout, ConnectionError, Timeout

requests.packages.urllib3.disable_warnings()

logger = logging.getLogger("netscaler")
logger.setLevel(logging.INFO)

class NetscalerError(Exception):
    pass

class NetscalerClient:
    def __init__(self, host: str, username: str, password: str, timeout: int = 30):
        self.host = host
        self.username = username
        self.password = password
        self.timeout = timeout
        self.base = f"https://{self.host}/nitro/v1/config"
        self.session = requests.Session()
        self.session.verify = False
        self._login()

    # ---------------- Internal ----------------
    def _login(self):
        url = f"https://{self.host}/nitro/v1/config/login"
        payload = {"login": {"username": self.username, "password": self.password}}
        try:
            r = self.session.post(url, json=payload, timeout=self.timeout)
            if r.status_code not in (200, 201):
                raise NetscalerError(f"Login failed: {r.status_code} {r.text}")
            logger.info("Logged in to NetScaler: %s", self.host)
        except (ConnectTimeout, ConnectionError, Timeout) as e:
            raise NetscalerError(f"Connection failed: {str(e)}")
        except requests.RequestException as e:
            raise NetscalerError(f"Request failed: {str(e)}")

    def _logout(self):
        try:
            self.session.post(f"https://{self.host}/nitro/v1/config/logout", timeout=self.timeout)
        except Exception:
            pass

    def _get(self, path: str, params: Optional[Dict] = None):
        return self.session.get(f"{self.base}{path}", params=params, timeout=self.timeout)

    def _post(self, path: str, payload: dict):
        return self.session.post(f"{self.base}{path}", json=payload, timeout=self.timeout)

    def _put(self, path: str, payload: dict):
        return self.session.put(f"{self.base}{path}", json=payload, timeout=self.timeout)

    def _delete(self, path: str):
        return self.session.delete(f"{self.base}{path}", timeout=self.timeout)

    # ---------------- Existence helpers ----------------
    def lbvserver_exists(self, name: str) -> bool:
        return self._get(f"/lbvserver/{name}").status_code == 200

    def servicegroup_exists(self, sg_name: str) -> bool:
        return self._get(f"/servicegroup/{sg_name}").status_code == 200

    def monitor_exists(self, mon: str) -> bool:
        return self._get(f"/lbmonitor/{mon}").status_code == 200

    def certkey_exists(self, key: str) -> bool:
        return self._get(f"/sslcertkey/{key}").status_code == 200

    # ---------------- Service Group ----------------
    def create_servicegroup(self, sg_name: str, servicetype: str = "HTTP"):
        if self.servicegroup_exists(sg_name):
            logger.info("Servicegroup %s already exists", sg_name)
            return True
        payload = {"servicegroup": {"servicegroupname": sg_name, "servicetype": servicetype}}
        r = self._post("/servicegroup", payload)
        if r.status_code not in (200, 201):
            raise NetscalerError(f"Servicegroup create failed: {r.status_code} {r.text}")
        logger.info("Servicegroup created: %s", sg_name)
        return True

    def add_service_member(self, sg_name: str, ip: str, port: int):
        payload = {
            "servicegroup_servicegroupmember_binding": {
                "servicegroupname": sg_name,
                "ip": ip,
                "port": int(port)
            }
        }
        try:
            r = self._post("/servicegroup_servicegroupmember_binding", payload)
            if r.status_code in (200, 201):
                logger.info("Added member %s:%s to %s", ip, port, sg_name)
                return True
            if r.status_code == 409 or "already exists" in r.text.lower():
                logger.warning("Member %s:%s already exists in %s", ip, port, sg_name)
                return True
            logger.warning("Failed to add member %s:%s to %s: %s %s", ip, port, sg_name, r.status_code, r.text)
            return False
        except Exception as e:
            logger.warning("Failed to add member %s:%s to %s: %s", ip, port, sg_name, str(e))
            return False

    # ---------------- LB vServer ----------------
    def create_lbvserver(self, vname: str, vip: str, port: int, servicetype: str = "HTTP"):
        if self.lbvserver_exists(vname):
            logger.info("LB vserver %s already exists", vname)
            return True
        payload = {"lbvserver": {"name": vname, "ipv46": vip, "port": int(port), "servicetype": servicetype}}
        r = self._post("/lbvserver", payload)
        if r.status_code not in (200, 201):
            raise NetscalerError(f"create_lbvserver failed: {r.status_code} {r.text}")
        logger.info("LB vserver created: %s (%s:%s)", vname, vip, port)
        return True

    def delete_lbvserver(self, name: str):
        r = self._delete(f"/lbvserver/{name}")
        if r.status_code in (200, 201, 204):
            logger.info("Deleted vserver: %s", name)
            return True
        raise NetscalerError(f"delete_lbvserver failed: {r.status_code} {r.text}")

    def update_lbvserver(self, name: str, **kwargs):
        payload = {"lbvserver": {"name": name}}
        payload["lbvserver"].update(kwargs)
        r = self._put(f"/lbvserver/{name}", payload)
        if r.status_code in (200, 201):
            logger.info("Updated vserver %s", name)
            return True
        raise NetscalerError(f"update_lbvserver failed: {r.status_code} {r.text}")

    # ---------------- Bind SG <-> vServer ----------------
    def bind_servicegroup_to_vserver(self, vname: str, sg_name: str):
        payload = {"lbvserver_servicegroup_binding": {"name": vname, "servicegroupname": sg_name}}
        r = self._post("/lbvserver_servicegroup_binding", payload)
        if r.status_code in (200, 201):
            logger.info("Bound servicegroup %s to vserver %s", sg_name, vname)
            return True
        if r.status_code == 409 or "already exists" in r.text.lower():
            logger.warning("Servicegroup %s already bound to vserver %s", sg_name, vname)
            return True
        raise NetscalerError(f"bind_servicegroup_to_vserver failed: {r.status_code} {r.text}")

    # ---------------- SSL Cert Binding ----------------
    def bind_ssl_cert_to_vserver(self, vname: str, certkey_name: str, priority: int = 100):
        if not self.certkey_exists(certkey_name):
            raise NetscalerError(f"CertKey {certkey_name} does not exist on NetScaler")
        payload = {"sslvserver_sslcertkey_binding": {"vservername": vname, "certkeyname": certkey_name, "priority": int(priority)}}
        r = self._post("/sslvserver_sslcertkey_binding", payload)
        if r.status_code in (200, 201):
            logger.info("Bound SSL cert %s to vserver %s", certkey_name, vname)
            return True
        if r.status_code == 409 or "already exists" in r.text.lower():
            logger.warning("SSL cert %s already bound to vserver %s", certkey_name, vname)
            return True
        raise NetscalerError(f"bind_ssl_cert_to_vserver failed: {r.status_code} {r.text}")

    # ---------------- Monitor binding (FIXED) ----------------
    def bind_monitor_to_servicegroup(self, sg_name: str, monitor_name: str):
        if not self.servicegroup_exists(sg_name):
            raise NetscalerError(f"ServiceGroup {sg_name} does not exist")
        if not self.monitor_exists(monitor_name):
            raise NetscalerError(f"Monitor {monitor_name} does not exist")
        payload = {
            "servicegroup_lbmonitor_binding": {
                "servicegroupname": sg_name,
                "monitor_name": monitor_name
            }
        }
        r = self._post("/servicegroup_lbmonitor_binding", payload)
        if r.status_code in (200, 201):
            logger.info("Monitor %s bound to servicegroup %s", monitor_name, sg_name)
            return True
        if r.status_code == 409 or "already exists" in r.text.lower():
            logger.warning("Monitor %s already bound to servicegroup %s", monitor_name, sg_name)
            return True
        raise NetscalerError(f"bind_monitor failed: {r.status_code} {r.text}")

    def unbind_monitor_from_servicegroup(self, sg_name: str, monitor_name: str):
        path = f"/servicegroup_lbmonitor_binding?servicegroupname={sg_name}&monitor_name={monitor_name}"
        r = self._delete(path)
        if r.status_code in (200, 201, 204):
            logger.info("Unbound monitor %s from servicegroup %s", monitor_name, sg_name)
            return True
        raise NetscalerError(f"unbind monitor failed: {r.status_code} {r.text}")

    # ---------------- Inventory helpers ----------------
    def get_lbvservers(self) -> List[Dict]:
        r = self._get("/lbvserver")
        if r.status_code != 200:
            raise NetscalerError(f"get_lbvservers failed: {r.status_code} {r.text}")
        return r.json().get("lbvserver", [])

    def get_servicegroup_members(self, sg_name: str) -> List[Dict]:
        r = self._get(f"/servicegroup_servicegroupmember_binding?servicegroupname={sg_name}")
        if r.status_code != 200:
            raise NetscalerError(f"get_servicegroup_members failed: {r.status_code} {r.text}")
        return r.json().get("servicegroup_servicegroupmember_binding", [])

    # ---------------- High-level create_vip ----------------
    def create_vip(self,
                   vip_name: str,
                   vip: str,
                   vip_port: int,
                   servicetype: str,
                   sg_name: str,
                   nodes: List[str],
                   monitor: Optional[str] = None,
                   certkey: Optional[str] = None):
        vname = vip_name
        added_members = []
        failed_members = []

        # create SG
        self.create_servicegroup(sg_name, servicetype)

        # add members - continue even if some fail
        for n in nodes:
            try:
                ip, prt = n.split(":")
                ip = ip.strip()
                port = int(prt)
                if self.add_service_member(sg_name, ip, port):
                    added_members.append(f"{ip}:{port}")
                else:
                    failed_members.append(f"{ip}:{port}")
            except ValueError as e:
                logger.warning("Invalid node format '%s': %s", n, str(e))
                failed_members.append(n)
            except Exception as e:
                logger.warning("Error processing node '%s': %s", n, str(e))
                failed_members.append(n)

        # create vserver
        self.create_lbvserver(vname, vip, vip_port, servicetype)
        # bind SG
        self.bind_servicegroup_to_vserver(vname, sg_name)
        # bind SSL if required
        if servicetype.upper() == "SSL" and certkey:
            self.bind_ssl_cert_to_vserver(vname, certkey)
        # bind monitor if provided
        if monitor:
            self.bind_monitor_to_servicegroup(sg_name, monitor)

        return {
            'vip_name': vname,
            'added_members': added_members,
            'failed_members': failed_members
        }

    # ---------------- Cleanup ----------------
    def close(self):
        self._logout()
        self.session.close()
        logger.info("Session closed")