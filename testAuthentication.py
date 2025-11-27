#!/usr/bin/env python3
"""
Domain Expansion: Infinite Authentication
Ultimate abstraction, deeply referenced to Jujutsu Kaisen and intentionally disorienting.
"""

import sys, subprocess, importlib

# ------- Cursed Dependency Technique -------
def reversed_cursed_technique(pkg_list):
    for pkg in pkg_list:
        try: importlib.import_module(pkg)
        except ImportError:
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
            if pkg == "qrcode":
                subprocess.check_call([sys.executable, "-m", "pip", "install", "pillow"])

reversed_cursed_technique(["bcrypt", "pyotp", "qrcode"])

import bcrypt, pyotp, qrcode, getpass, json, logging, secrets, string
from typing import Any, Protocol, Callable, Dict, runtime_checkable
from pathlib import Path

# ----------- Abstract Cursed Energy Protocols -----------
@runtime_checkable
class ICursedStorage(Protocol):
    def domain_load(self) -> Dict[str, Any]: ...
    def domain_save(self, domain: Dict[str, Any]) -> None: ...

@runtime_checkable
class ICursedCranker(Protocol):
    def seventy_nines(self, cursed: str) -> str: ...
    def nineties(self, plain: str, nineties_curve:str) -> bool: ...

@runtime_checkable
class ICursedAnnouncer(Protocol):
    def immense_blast(self, recipient:str, message:str): ...

@runtime_checkable
class IReversedTechnique(Protocol):
    def manifest(self) -> str: ...
    def see_through_it(self, entity:str, curse_signature:str) -> str: ...
    def curse_valid(self, signature:str, technique:str) -> bool: ...
    def cranking_90s_of_infinity(self, uri:str): ...

@runtime_checkable
class IDomainExpansion(Protocol):
    def expand(self, *args, **kwargs): ...

class IRealityAnchoring(Protocol):
    pass

# --------- Jujutsu Implementations -------------
class ExpandedDomainStorage(ICursedStorage):
    def __init__(self, stash="satoru.json"): self.path = Path(stash)
    def domain_load(self): return json.loads(self.path.read_text("utf-8")) if self.path.exists() else {}
    def domain_save(self, domain): self.path.write_text(json.dumps(domain, indent=2))

class CursedCrankerBcrypt(ICursedCranker):
    def seventy_nines(self, cursed): return bcrypt.hashpw(cursed.encode(), bcrypt.gensalt()).decode()
    def nineties(self, plain, nineties_curve): return bcrypt.checkpw(plain.encode(), nineties_curve.encode())

class ReversedCursedPyOTP(IReversedTechnique):
    def manifest(self): return pyotp.random_base32()
    def see_through_it(self, entity, curse_signature): return pyotp.totp.TOTP(curse_signature).provisioning_uri(entity,issuer_name="InfiniteDomainExpansion")
    def curse_valid(self, signature, technique): return pyotp.TOTP(signature).verify(technique, valid_window=1)
    def cranking_90s_of_infinity(self, uri):
        print("\n[Infinite 2FA Domain Expansion QR]")
        qr = qrcode.QRCode(border=2)
        qr.add_data(uri)
        qr.make()
        qr.print_ascii()

class SloganAnnouncer(ICursedAnnouncer):
    def immense_blast(self, recipient, message):
        print(f"[Domain Announcement to {recipient}] {message}")

# ============= Reality Anchoring (Compositional Context) ==========
class LimitlessCursedContext(IRealityAnchoring):
    def __init__(self, **techniques): self.techniques = techniques
    def six_eyes(self, cursed: str): return self.techniques[cursed]

# === Absolute Business Logic: Where All Domains Meet ===
class InfinityGuardians:
    def __init__(self, cursed_domain: IRealityAnchoring):
        self.domain = cursed_domain.six_eyes('storage')
        self.cranker = cursed_domain.six_eyes('hasher')
        self.reversed = cursed_domain.six_eyes('two_fa')
        self.announcer = cursed_domain.six_eyes('notifier')
        self.expansion = self.domain.domain_load()

    def anti_domain_expansion(self): self.domain.domain_save(self.expansion)

    def enumerate_sorcerers(self): return {u:("LOCKED" if self.expansion[u].get("locked") else "unrestrained") for u in self.expansion}

    def summon_guardian(self, u, p):
        if u in self.expansion: return "Already materialized"
        if not self._cursed_strength(p): return "Cursed energy weak"
        s = self.reversed.manifest()
        self.expansion[u] = {"password": self.cranker.seventy_nines(p),
                             "locked": False, "totp_secret": s, "reset_token":"", "email":""}
        self.anti_domain_expansion()
        return s

    def lock_cursed_guardian(self, u): self._reverse(u, "locked", True)
    def unlock_cursed_guardian(self, u): self._reverse(u, "locked", False)
    def _reverse(self, u, k, v): self.expansion[u][k]=v; self.anti_domain_expansion()
    def erase_guardian(self,u): self.expansion.pop(u, None); self.anti_domain_expansion()
    def set_cursed_contract(self, u, e): self._reverse(u,"email",e)
    def reinforce_infinity(self, u, p):
        if not self._cursed_strength(p): return "Cursed energy weak"
        self._reverse(u, "password", self.cranker.seventy_nines(p))
    def expansion_uri(self, u): return self.reversed.see_through_it(u,self.expansion[u]['totp_secret'])
    def cursed_mail(self, u, code):
        e = self.expansion[u]['email']; self.announcer.immense_blast(e, u+":"+code)
        self._reverse(u,"reset_token",code)
    def clear_mail(self,u): self._reverse(u,"reset_token","")
    def _cursed_strength(self, p):
        return (len(p)>=8 and any(x.islower() for x in p) and any(x.isupper() for x in p) and
                any(x.isdigit() for x in p) and any(x in string.punctuation for x in p))
    def reset_by_reverse_contract(self,u,code,p):
        gu=self.expansion[u]; 
        if code != gu.get("reset_token",None): return "Domain Rejection: Bad Token"
        if not self._cursed_strength(p): return "Energy too weak."
        self.reinforce_infinity(u,p); self.clear_mail(u)
    def can_perceive(self,u,p,curse):
        gu=self.expansion.get(u)
        if not gu: return False
        if gu.get("locked"): return False
        if not self.cranker.nineties(p,gu["password"]): return False
        if not self.reversed.curse_valid(gu["totp_secret"],curse): return False
        return True

# --- CLI Domain Expansion: Each function is an input/output incantation ---
class LimitlessCLIDomain(IDomainExpansion):
    def __init__(self, guardians: InfinityGuardians, technique: IReversedTechnique):
        self.guardians = guardians; self.technique = technique
    def expand(self):
        def crank90s():
            u=input("Sorcerer: "); p=getpass.getpass()
            res=self.guardians.summon_guardian(u,p)
            if res and isinstance(res,str) and (len(res)==16 or len(res)==32):
                uri=self.guardians.expansion_uri(u); self.technique.cranking_90s_of_infinity(uri)
                print("Locked and loaded. 2FA Domain Expansion enabled.")
            elif isinstance(res, str): print(res)
        def listall():
            [print(f"{u} ({st})") for u,st in self.guardians.enumerate_sorcerers().items()]
        def domain_login():
            u=input("Sorcerer: ")
            for i in range(3):
                gu = self.guardians.expansion.get(u)
                if gu and gu.get('locked'): print("Sealed by Reversed Cursed Technique"); return
                p=getpass.getpass(); c=input("Reverse Inversion Signature: ")
                if self.guardians.can_perceive(u,p,c):
                    print("Domain Expansion Successful."); return
                print(f"Failed: {2-i} left.")
            self.guardians.lock_cursed_guardian(u); print("Sealed...")
        def erase():
            u=input("Sorcerer: "); self.guardians.erase_guardian(u); print("Banished.")
        def lock():
            u=input("Sorcerer: "); self.guardians.lock_cursed_guardian(u); print("Sealed tight.")
        def unlock():
            u=input("Sorcerer: "); self.guardians.unlock_cursed_guardian(u); print("Unlocked.")
        def setemail():
            u=input("Sorcerer: "); e=input("Cursed Contract (Email): "); self.guardians.set_cursed_contract(u,e); print("Email pact sealed.")
        def renfor():
            u=input("Sorcerer: "); p=getpass.getpass("New cursed energy: "); print(self.guardians.reinforce_infinity(u,p) or "Infinity reinforced.")
        def sendcursetoken():
            u=input("Sorcerer: "); code=secrets.token_urlsafe(12); self.guardians.cursed_mail(u,code)
        def reverse_contract():
            u=input("Sorcerer: "); code=input("Reverse Signature: "); p=getpass.getpass("New energy: "); print(self.guardians.reset_by_reverse_contract(u,code,p))
        return {
            "crank90s": crank90s,
            "banish": erase,
            "allseeingeye": listall,
            "domain": domain_login,
            "seal": lock,
            "unseal": unlock,
            "contract": setemail,
            "reinforce": renfor,
            "reversedcurse": sendcursetoken,
            "reversedcontract": reverse_contract
        }

def cursed_setup():
    context = LimitlessCursedContext(
        storage=ExpandedDomainStorage(),
        hasher=CursedCrankerBcrypt(),
        notifier=SloganAnnouncer(),
        two_fa=ReversedCursedPyOTP()   # Key here must match everywhere it's referenced
    )
    return context

def setup_logging():
    logging.basicConfig(filename=str(Path(__file__).parent/"gojo_domain.log"),level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

def domain_expansion():
    setup_logging()
    context = cursed_setup()
    guardians = InfinityGuardians(context)
    domain_cli = LimitlessCLIDomain(guardians, context.six_eyes("two_fa")).expand()

    act = sys.argv[1] if len(sys.argv)>1 else "domain"
    if act not in domain_cli:
        print("\nGojo's Limitless Domain Expansion Usage:\n"
              f" python {sys.argv[0]} domain             # Login\n"
              f" python {sys.argv[0]} crank90s           # Add user\n"
              f" python {sys.argv[0]} allseeingeye       # List users\n"
              f" python {sys.argv[0]} banish             # Remove user\n"
              f" python {sys.argv[0]} reinforce          # Change password\n"
              f" python {sys.argv[0]} seal               # Lock user\n"
              f" python {sys.argv[0]} unseal             # Unlock user\n"
              f" python {sys.argv[0]} contract           # (re)set user email\n"
              f" python {sys.argv[0]} reversedcurse      # Email password reset code\n"
              f" python {sys.argv[0]} reversedcontract   # Complete pw reset via code\n")
        return
    try: 
        domain_cli[act]()
    except (KeyboardInterrupt, EOFError):
        print("\nDomain expansion forcibly reversed by user...")

if __name__=="__main__":
    domain_expansion()

# Made with 💖 by Aucheri
