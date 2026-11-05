#!/usr/bin/env python3
"""Data figures for the post-quantum IoT authentication study (vector PDF, Springer/Elsevier widths)."""
import argparse, csv, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter, LogLocator, NullFormatter

MM = 1 / 25.4
plt.rcParams.update({
    "font.family": "STIXGeneral", "mathtext.fontset": "stix", "font.size": 8.5, "axes.labelsize": 8.5,
    "xtick.labelsize": 7.5, "ytick.labelsize": 7.5, "legend.fontsize": 7.0, "axes.linewidth": 0.6,
    "xtick.direction": "in", "ytick.direction": "in", "xtick.top": True, "ytick.right": True,
    "lines.linewidth": 1.2, "lines.markersize": 4.2, "legend.frameon": False,
    "pdf.fonttype": 42, "savefig.bbox": "tight", "savefig.pad_inches": 0.02})
OK = {"blue": "#0072B2", "orange": "#E69F00", "green": "#009E73", "pink": "#CC79A7", "verm": "#D55E00",
      "sky": "#56B4E9", "yellow": "#F0E442", "black": "#000000", "grey": "#7F7F7F"}
thousands = FuncFormatter(lambda v, _: f"{int(v):,}" if v >= 1 else f"{v:g}")
read = lambda p: list(csv.DictReader(open(p)))


def save(fig, out, name):
    fig.savefig(os.path.join(out, name + ".pdf")); fig.savefig(os.path.join(out, name + ".png"), dpi=300); plt.close(fig)


# ------------------------------------------------------------------ Fig. 2: device-side costs
def fig_device(off, out):
    rows = read(os.path.join(off, "pq_device_c.csv"))
    order = ["ECDSA secp256k1", "ECDSA P-256", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
             "Falcon-512", "Falcon-1024", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-128s"]
    R = {r["scheme"]: r for r in rows}
    names = [n.replace("SLH-DSA-SHA2-", "SLH-DSA-") for n in order]
    col = [OK["grey"], OK["grey"], OK["blue"], OK["blue"], OK["blue"], OK["orange"], OK["orange"], OK["green"], OK["green"]]
    fig, (a, b) = plt.subplots(1, 2, figsize=(174 * MM, 58 * MM))
    y = list(range(len(order)))[::-1]
    a.barh(y, [float(R[n]["sign_ms"]) for n in order], color=col, height=0.62, edgecolor="black", lw=0.4)
    a.barh([v - 0.0 for v in y], [float(R[n]["verify_ms"]) for n in order], height=0.25, color="white", edgecolor="black", lw=0.4, hatch="////")
    a.set_xscale("log"); a.set_yticks(y); a.set_yticklabels(names); a.set_xlabel("Time on one x86-64 core, C implementations (ms, log scale)")
    a.set_xlim(0.01, 20000); a.grid(True, axis="x", which="major", lw=0.4, color="0.85"); a.set_axisbelow(True)
    a.tick_params(axis="y", length=0)
    for yi, n in zip(y, order):
        x = max(float(R[n]["sign_ms"]), float(R[n]["verify_ms"]))
        a.text(x * 1.25, yi, f'{float(R[n]["sign_ms"]):.3g} / {float(R[n]["verify_ms"]):.2g}', va="center", fontsize=6.6)
    from matplotlib.patches import Patch
    a.legend(handles=[Patch(facecolor="0.6", edgecolor="black", lw=0.4, label="sign"),
                      Patch(facecolor="white", edgecolor="black", lw=0.4, hatch="////", label="verify")],
             loc="lower right", bbox_to_anchor=(1.0, 1.0), ncol=2, borderaxespad=0.2)
    a.text(0.0, 1.03, "(a) sign / verify (ms)", transform=a.transAxes, fontweight="bold")

    sig = [int(R[n]["sig_bytes"]) for n in order]; pk = [int(R[n]["pk_bytes"]) for n in order]
    b.barh([v + 0.17 for v in y], sig, height=0.34, color=col, edgecolor="black", lw=0.4, label="signature")
    b.barh([v - 0.17 for v in y], pk, height=0.34, color="white", edgecolor=col, lw=0.8, hatch="....", label="public key")
    b.set_xscale("log"); b.set_yticks(y); b.set_yticklabels([]); b.set_xlabel("Size (bytes, log scale)")
    b.set_xlim(20, 200000); b.xaxis.set_major_formatter(thousands)
    for yi, s in zip(y, sig): b.text(s * 1.15, yi + 0.17, f"{s:,}", va="center", fontsize=6.8)
    b.grid(True, axis="x", which="major", lw=0.4, color="0.85"); b.set_axisbelow(True); b.tick_params(axis="y", length=0)
    b.legend(loc="lower right", bbox_to_anchor=(1.0, 1.0), ncol=2, borderaxespad=0.2)
    b.text(0.0, 1.03, "(b)", transform=b.transAxes, fontweight="bold")
    fig.tight_layout(w_pad=1.0); save(fig, out, "fig2_device")


# ------------------------------------------------------------------ Fig. 3: per-record breakdown (revised contract)
def fig_breakdown(prjson, out, n=50):
    import json
    d = json.load(open(prjson))
    rows = {(r["scheme"], r["impl"]): r for r in d["pr"] if r["config"] == "n=50" and r.get("gas")}
    pick = [("ECDSA", "ecrecover", "ECDSA secp256k1"), ("Falcon-512", "Precompile EIP-8052", "Falcon-512, EIP-8052"),
            ("ML-DSA-44", "Precompile EIP-8355", "ML-DSA-44, EIP-8355"), ("ML-DSA-65", "Precompile EIP-8355", "ML-DSA-65, EIP-8355"),
            ("ML-DSA-87", "Precompile EIP-8355", "ML-DSA-87, EIP-8355"), ("LMS-H10-W4", "Solidity LMS (real)", "LMS-H10-W4, Solidity"),
            ("SLH-DSA-128s", "none (data cost only)", "SLH-DSA-128s, data only")]
    fig, ax = plt.subplots(figsize=(174 * MM, 58 * MM)); labels = []
    for i, (s_, impl, lab) in enumerate(pick):
        r = rows.get((s_, impl))
        if r is None: continue
        z, nz, ex = r["zero_bytes"], r["nonzero_bytes"], r["exec"]
        exe, std, flo = ex / n, (4 * z + 16 * nz) / n, (10 * z + 40 * nz) / n
        top = max(0.0, flo - std - exe); yi = len(pick) - 1 - i; labels.append((yi, lab))
        ax.barh(yi, exe, color=OK["blue"], height=0.6, edgecolor="black", lw=0.4, label="execution" if i == 0 else None)
        ax.barh(yi, std, left=exe, color=OK["orange"], height=0.6, edgecolor="black", lw=0.4, label="calldata (standard price)" if i == 0 else None)
        ax.barh(yi, top, left=exe + std, color="white", height=0.6, edgecolor=OK["verm"], hatch="xxxx", lw=0.6, label="EIP-7623 floor top-up" if i == 0 else None)
        ax.text(max(exe + std + top, exe + std) + 1500, yi, f"{r['per_record']:,}", va="center", fontsize=7.5)
    ax.set_yticks([l[0] for l in labels]); ax.set_yticklabels([l[1] for l in labels]); ax.tick_params(axis="y", length=0)
    ax.xaxis.set_major_formatter(thousands); ax.set_xlabel(f"Gas per record (batches of $n$ = {n} records from 10 devices, replay-protected contract)")
    ax.set_xlim(0, 400_000); ax.grid(True, axis="x", lw=0.4, color="0.85"); ax.set_axisbelow(True)
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=3, borderaxespad=0.3)
    fig.tight_layout(); save(fig, out, "fig3_per_record_breakdown")


# ------------------------------------------------------------------ Fig. 4: device-signed roots
def fig_device_root(on2, out):
    rows = read(os.path.join(on2, "pq4_dr.csv"))
    S = [("ECDSA", "ecrecover", "ECDSA secp256k1 (same design)", dict(color=OK["black"], marker="o", ls="-")),
         ("ML-DSA-44", "Precompile EIP-8355", "ML-DSA-44, precompile EIP-8355", dict(color=OK["blue"], marker="s", ls="-")),
         ("Falcon-512", "Precompile EIP-8052", "Falcon-512, precompile EIP-8052", dict(color=OK["orange"], marker="^", ls="-")),
         ("LMS-H10-W4", "Solidity LMS (real)", "LMS-H10-W4, Solidity (today)", dict(color=OK["green"], marker="D", ls="--")),
         ("ML-DSA-44", "Solidity, NIST (optimized)", "ML-DSA-44, Solidity NIST (today)", dict(color=OK["sky"], marker="v", ls="--")),
         ("Falcon-512", "Solidity, EVM-friendly", "Falcon-512, Solidity EVM-friendly (today)", dict(color=OK["pink"], marker="P", ls=":"))]
    fig, (a, b) = plt.subplots(1, 2, figsize=(174 * MM, 72 * MM), sharey=True)
    for s_, impl, lab, st in S:
        pts = sorted((int(r["k"]), int(r["per_record"])) for r in rows if r["variant"].startswith("DR-L") and r["scheme"] == s_ and r["impl"] == impl)
        if pts: a.plot(*zip(*pts), label=lab, mfc="white", **st)
        var = "DR-0 " if s_ in ("ECDSA", "LMS-H10-W4") else "DR-0C"
        r1 = [r for r in rows if r["variant"].startswith(var) and r["scheme"] == s_ and r["impl"] == impl and int(r["k"]) == 1]
        if r1:
            tx = int(r1[0]["tx_gas"]); ks = [1, 10, 100, 1000, 10000]
            b.plot(ks, [tx / (10 * k) for k in ks], mfc="white", **st)
    for ax, t in ((a, "(a) leaves posted (DR-L)"), (b, "(b) root only (DR-0); PQ keys stored on-chain")):
        ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xticks([1, 10, 100, 1000, 10000]); ax.set_xticklabels(["1", "10", "100", "1,000", "10,000"])
        ax.yaxis.set_major_formatter(thousands); ax.yaxis.set_minor_formatter(NullFormatter())
        ax.grid(True, which="major", lw=0.4, color="0.85"); ax.grid(True, which="minor", lw=0.25, color="0.93"); ax.set_axisbelow(True)
        ax.set_xlabel("Records per device-signed root, $k$"); ax.set_title(t, fontsize=8.5, loc="left")
    a.set_xlim(0.8, 1400); b.set_xlim(0.8, 14000); a.set_ylim(1, 3e6); a.set_ylabel("Gas per record")
    a.legend(loc="lower left", fontsize=6.6, handlelength=2.4)
    fig.tight_layout(w_pad=1.0); save(fig, out, "fig4_device_root")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--onchain", default="../../pq/onchain/results"); ap.add_argument("--offchain", default="../offchain/results")
    ap.add_argument("--onchain2", default="../onchain/results4")
    ap.add_argument("--prjson", default="/home/claude/pq3/onchain/results3/pq3_pr_warm.json")
    ap.add_argument("--out", default="out")
    a = ap.parse_args(); os.makedirs(a.out, exist_ok=True)
    fig_device(a.offchain, a.out); fig_breakdown(a.prjson, a.out); fig_device_root(a.onchain2, a.out)
    print("figures written to", a.out)
