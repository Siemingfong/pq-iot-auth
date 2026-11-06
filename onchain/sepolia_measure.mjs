// Gas measurement on a live network (Sepolia) for the designs that need no draft precompile:
// ECDSA (ecrecover), P-256 (EIP-7951 precompile), and LMS/HSS verified in Solidity.
// Transaction builders are copied verbatim from pq_gasbench10.mjs; only the backend differs
// (JSON-RPC instead of the EthereumJS VM), and the chain ID is read from the network.
//
// Usage (GitHub Actions: .github/workflows/sepolia.yml):
//   SEPOLIA_RPC_URL=... SEPOLIA_PRIVATE_KEY=0x... node sepolia_measure.mjs
// Optional: SCHEMES (comma-separated), EXPECT_CHAIN_ID (default 11155111), DRY_RUN=1 (estimate only)
import fs from 'node:fs'
import crypto from 'node:crypto'
import { spawn } from 'node:child_process'
import readline from 'node:readline'
import solc from 'solc'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { p256 } from '@noble/curves/nist.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { AbiCoder, Interface, JsonRpcProvider, Wallet, formatEther } from 'ethers'

const OUT = 'results-sepolia'; fs.mkdirSync(OUT, { recursive: true })
const CAP = 16_777_216n
const abi = AbiCoder.defaultAbiCoder()
const rnd = (b) => '0x' + crypto.randomBytes(b).toString('hex')
const hex = (u8) => '0x' + Buffer.from(u8).toString('hex')
const hexToBytes = (h) => Uint8Array.from(Buffer.from(h.replace(/^0x/, ''), 'hex'))
const kec = (h) => hex(keccak_256(hexToBytes(h)))
const log = (...a) => console.log(...a)
const STUB = '0x000000000000000000000000000000000000ab12'   // never called: ECDSA and P-256 use ecrecover / 0x100

// ------------------------------------------------------------------ network and safety checks
const RPC = process.env.SEPOLIA_RPC_URL, KEY = process.env.SEPOLIA_PRIVATE_KEY
if (!RPC || !KEY) { console.error('Set SEPOLIA_RPC_URL and SEPOLIA_PRIVATE_KEY'); process.exit(1) }
const provider = new JsonRpcProvider(RPC, undefined, { polling: true, pollingInterval: 3000 })
const wallet = new Wallet(KEY, provider)
const net = await provider.getNetwork()
const CHAIN_ID = net.chainId
const EXPECT = BigInt(process.env.EXPECT_CHAIN_ID || '11155111')
if (CHAIN_ID === 1n) { console.error('Refusing to run on Ethereum mainnet.'); process.exit(1) }
if (CHAIN_ID !== EXPECT) { console.error(`Chain ID ${CHAIN_ID} is not the expected ${EXPECT}.`); process.exit(1) }
const SCHEMES = (process.env.SCHEMES || 'ECDSA,P-256,LMS-H10-W4,LMS-H15-W4,LMS-HSS-H10W4x2').split(',').map(s => s.trim()).filter(Boolean)
const M = 10, K = 100
const PLANNED_GAS = { base: 30_000_000, 'ECDSA': 5_000_000, 'P-256': 2_500_000, 'LMS-H10-W4': 9_000_000, 'LMS-H15-W4': 9_500_000, 'LMS-HSS-H10W4x2': 16_000_000, lmsDeploy: 12_000_000 }
const planned = BigInt(PLANNED_GAS.base + SCHEMES.reduce((a, s) => a + (PLANNED_GAS[s] || 10_000_000), 0) + (SCHEMES.some(s => s.startsWith('LMS')) ? PLANNED_GAS.lmsDeploy : 0))
const fee = await provider.getFeeData(), bal = await provider.getBalance(wallet.address)
const price = fee.maxFeePerGas ?? fee.gasPrice
const need = planned * price
const head = await provider.getBlock('latest')
let client = ''; try { client = await provider.send('web3_clientVersion', []) } catch {}
log(`chain ${CHAIN_ID}, block ${head.number}, gas limit ${head.gasLimit}, base fee ${head.baseFeePerGas} wei, client ${client}`)
log(`wallet ${wallet.address}, balance ${formatEther(bal)} ETH; planned ~${planned / 1_000_000n}M gas, ~${formatEther(need)} ETH at ${price} wei/gas`)
if (bal < need) { console.error(`Balance too low: need about ${formatEther(need)} ETH (with this gas price). Fund the wallet or lower SCHEMES.`); process.exit(1) }
if (process.env.DRY_RUN) { log('DRY_RUN: stopping before any transaction.'); process.exit(0) }

// ------------------------------------------------------------------ LMS signing service (same as the harness)
const LMS = ['LMS-H10-W2', 'LMS-H10-W4', 'LMS-H10-W8', 'LMS-H15-W4', 'LMS-HSS-H10W4x2', 'LMS-M24-H10-W4', 'LMS-HSS-M24-H10W4x2', 'LMS-M24-H15-W4']
const lmsKey = (s) => s.slice(4)
let lmsProc = null, lmsCall = null
if (SCHEMES.some(s => LMS.includes(s))) {
  lmsProc = spawn('python3', ['lms_signer.py'], { stdio: ['pipe', 'pipe', 'inherit'] })
  const lines = readline.createInterface({ input: lmsProc.stdout }), q = []
  lines.on('line', (l) => q.shift()(JSON.parse(l)))
  lmsCall = (req) => new Promise((res) => { q.push(res); lmsProc.stdin.write(JSON.stringify(req) + '\n') })
}
const pqSig = () => { throw new Error('draft-precompile schemes are not measured on a live network') }

// ------------------------------------------------------------------ compile (same settings as the harness)
const srcs = { 'PQAnchor5.sol': { content: fs.readFileSync('PQAnchor5.sol', 'utf8') }, 'LMSVerifier2.sol': { content: fs.readFileSync('LMSVerifier2.sol', 'utf8') } }
const out = JSON.parse(solc.compile(JSON.stringify({ language: 'Solidity', sources: srcs,
  settings: { optimizer: { enabled: true, runs: 200 }, viaIR: true, evmVersion: 'cancun', outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } } })))
const errs = (out.errors || []).filter(e => e.severity === 'error')
if (errs.length) { console.error(errs.map(e => e.formattedMessage).join('\n')); process.exit(1) }
const C = { anchor: out.contracts['PQAnchor5.sol'].PQAnchor5, lms: out.contracts['LMSVerifier2.sol'].LMSVerifier2 }
const iA = new Interface(C.anchor.abi)

// ------------------------------------------------------------------ JSON-RPC backend
const TXS = []
const RES = { environment: { chain_id: Number(CHAIN_ID), start_block: head.number, block_gas_limit: head.gasLimit.toString(), client, solc: solc.version(), wallet: wallet.address, started: new Date().toISOString() },
  contracts: {}, transactions: TXS, measurements: [] }
const save = () => fs.writeFileSync(`${OUT}/sepolia_results.json`, JSON.stringify(RES, (k, v) => typeof v === 'bigint' ? v.toString() : v, 2))
const REJ = kec('0x' + Buffer.from('DeviceRejected(uint32,uint64)').toString('hex'))
const rejected = (r) => (r.logs || []).filter(l => l.topics[0] === REJ).length
async function send(label, to, data) {
  const req = { to: to || undefined, data }
  let gl
  try { gl = await wallet.estimateGas(req) } catch (e) { const msg = (e.shortMessage || e.message).slice(0, 200); TXS.push({ label, ok: false, error: 'estimateGas: ' + msg }); save(); return { ok: false, err: msg } }
  gl = gl * 12n / 10n + 50_000n; if (gl > CAP) gl = CAP
  for (let attempt = 1; ; attempt++) {
    try {
      const tx = await wallet.sendTransaction({ ...req, gasLimit: gl })
      const rc = await tx.wait()
      const r = { ok: rc.status === 1, total: Number(rc.gasUsed), addr: rc.contractAddress, hash: tx.hash, block: rc.blockNumber, logs: rc.logs, data }
      TXS.push({ label, ok: r.ok, gas_used: r.total, hash: r.hash, block: r.block, calldata_bytes: (data.length - 2) / 2 }); save()
      log(`${r.ok ? 'ok ' : 'FAIL'} ${label}: ${r.total} gas  ${r.hash}`)
      return r
    } catch (e) {
      if (attempt >= 3) throw e
      log(`retry ${label}: ${(e.shortMessage || e.message).slice(0, 120)}`); await new Promise(r => setTimeout(r, 5000 * attempt))
    }
  }
}
async function deploy(label, c, args = '') { const r = await send('deploy ' + label, null, '0x' + c.evm.bytecode.object + args); if (!r.ok) throw new Error('deploy ' + label + ' ' + r.err); RES.contracts[label] = r.addr; save(); return r }

// ------------------------------------------------------------------ builders copied verbatim from pq_gasbench10.mjs
let nextIdx = 0
const dev = {}, epoch = new Map(), seqa = new Map()
const ep = (a, i) => epoch.get(a + ':' + i) || 0
const PK = {}
async function register(anchor, key, scheme, m, mode) {   // mode: 'calldata' | 'code'
  dev[key] = dev[key] || []
  for (let j = dev[key].length; j < m; j++) {
    let d
    if (scheme === 'ECDSA') { const sk = secp256k1.utils.randomSecretKey(); d = { sk, pk: hex(keccak_256(secp256k1.getPublicKey(sk, false).slice(1)).slice(12)) } }
    else if (scheme === 'P-256') { const sk = p256.utils.randomSecretKey(); d = { sk, pk: hex(p256.getPublicKey(sk, false).slice(1)) } }
    else if (LMS.includes(scheme)) d = { pk: '0x' + (await lmsCall({ key: lmsKey(scheme), pk: true })).pk }
    else d = { pk: '0x' + PK[scheme] }
    d.idx = nextIdx++; d.commit = kec(d.pk)
    const fn = mode === 'code' ? 'registerDeviceCode' : 'registerDevice'
    const r = await send(`register ${scheme} #${j}`, anchor, iA.encodeFunctionData(fn, [d.idx, d.pk]))
    if (!r.ok) throw new Error('register ' + scheme + ' ' + r.err)
    d.reg = r.total; dev[key].push(d)
  }
  return dev[key]
}

function merkle(h) { let l = h.slice(); while (l.length > 1) { const n = []; for (let i = 0; i < l.length; i += 2) n.push(i + 1 < l.length ? kec('0x01' + l[i].slice(2) + l[i + 1].slice(2)) : l[i]); l = n } return l[0] }
const msgOf = (anchor, d, e, root, count) => kec(abi.encode(['uint256', 'address', 'bytes32', 'uint32', 'uint64', 'bytes32', 'uint32'], [CHAIN_ID, anchor.toString(), d.commit, d.idx, e, root, count]))
function ecdsaSig(sk, h) { const s = secp256k1.Signature.fromBytes(secp256k1.sign(hexToBytes(h), sk, { prehash: false, format: 'recovered' }), 'recovered'); return '0x' + s.r.toString(16).padStart(64, '0') + s.s.toString(16).padStart(64, '0') + (27 + s.recovery).toString(16) }
async function batch(anchor, scheme, ds, k, { leaves, keyOnChain }) {
  const entries = []
  for (const d of ds) {
    const e = ep(anchor, d.idx) + 1
    const lv = leaves ? Array.from({ length: k }, () => rnd(32)) : []
    const root = leaves ? merkle(lv) : rnd(32)
    const m = msgOf(anchor, d, e, root, k)
    let sig
    if (scheme === 'ECDSA') sig = ecdsaSig(d.sk, m)
    else if (scheme === 'P-256') sig = hex(p256.sign(hexToBytes(m), d.sk, { prehash: false, format: 'compact' }))
    else if (LMS.includes(scheme)) sig = '0x' + (await lmsCall({ key: lmsKey(scheme), msg: m.slice(2) })).sig
    else sig = pqSig(scheme)
    entries.push({ d, e, row: [d.idx, keyOnChain ? '0x' : d.pk, sig, e, root, k, lv] })
  }
  return { data: iA.encodeFunctionData('submit', [entries.map(x => x.row)]), entries }
}

async function sigFor(scheme, d, m) {
  if (scheme === 'ECDSA') return ecdsaSig(d.sk, m)
  if (scheme === 'P-256') return hex(p256.sign(hexToBytes(m), d.sk, { prehash: false, format: 'compact' }))
  if (LMS.includes(scheme)) return '0x' + (await lmsCall({ key: lmsKey(scheme), msg: m.slice(2) })).sig
  return pqSig(scheme)
}

async function abiPR(label, A, scheme, ds, per) {
  const rows = [], upd = []
  for (const d of ds) {
    const s0 = (seqa.get(A + ':' + d.idx) || 0) + 1, rr = []
    for (let i = 0; i < per; i++) {
      const rec = { ct: rnd(32), ts: BigInt(1_700_000_000 + i), chk: rnd(32), seed: rnd(20) }
      const leaf = kec('0x00' + abi.encode(['bytes32', 'uint64', 'bytes32', 'bytes20'], [rec.ct, rec.ts, rec.chk, rec.seed]).slice(2))
      const m = kec(abi.encode(['uint256', 'address', 'bytes32', 'uint32', 'uint64', 'bytes32'], [CHAIN_ID, A.toString(), d.commit, d.idx, s0 + i, leaf]))
      rr.push([rec.ct, rec.ts, rec.chk, rec.seed, await sigFor(scheme, d, m)])
    }
    rows.push([d.idx, d.pk, s0, rr]); upd.push([d, s0 + per - 1])
  }
  const r = await send(label, A, iA.encodeFunctionData('submitPR', [rows]))
  if (r.ok) for (const [d, l] of upd) seqa.set(A + ':' + d.idx, l)
  return r
}

async function run(label, anchor, scheme, ds, k, opt) {
  const b = await batch(anchor, scheme, ds, k, opt)
  const r = await send(label, anchor, b.data)
  if (r.ok) for (const x of b.entries) epoch.set(anchor + ':' + x.d.idx, x.e)
  return r
}
function record(design, scheme, r, nRec) {
  const nr = rejected(r)
  if (!r.ok || nr > 0) { RES.measurements.push({ design, scheme, ok: false, rejected: nr, hash: r.hash }); save(); log(`!! ${design} ${scheme}: failed or ${nr} rejected`); return }
  RES.measurements.push({ design, scheme, ok: true, tx_gas: r.total, records: nRec, per_record: Math.round(r.total / nRec), hash: r.hash, block: r.block }); save()
}

// ------------------------------------------------------------------ measurements (m = 10 devices; second submission is measured)
const salt = await provider.getTransactionCount(wallet.address)
nextIdx = Number(salt) * 1000                               // fresh device indices for every run
const ecA = (await deploy('anchor (ECDSA, P-256)', C.anchor, abi.encode(['address', 'bool'], [STUB, true]).slice(2))).addr
let lmsA = null
if (SCHEMES.some(s => LMS.includes(s))) {
  const v = await deploy('LMSVerifier2', C.lms)
  lmsA = (await deploy('anchor (LMS)', C.anchor, abi.encode(['address', 'bool'], [v.addr, true]).slice(2))).addr
}
const anchorOf = (s) => (LMS.includes(s) ? lmsA : ecA)
for (const s of SCHEMES) {
  const A = anchorOf(s)
  const ds = await register(A, s, s, M, 'calldata')
  RES.measurements.push({ design: 'registration (commitment)', scheme: s, per_device: Math.round(ds.reduce((a, d) => a + d.reg, 0) / ds.length) }); save()
  await run(`DR-0 ${s} warm-up`, A, s, ds, K, { leaves: false, keyOnChain: false })
  record('DR-0', s, await run(`DR-0 ${s}`, A, s, ds, K, { leaves: false, keyOnChain: false }), M * K)
  if (s === 'ECDSA') record('DR-L', s, await run(`DR-L ${s}`, A, s, ds, K, { leaves: true, keyOnChain: false }), M * K)
  if (s === 'ECDSA' || s === 'P-256') {
    await abiPR(`PR ${s} warm-up`, A, s, ds, 1)
    record('PR', s, await abiPR(`PR ${s}`, A, s, ds, 5), M * 5)
  }
  log(`done ${s}`)
}
RES.environment.finished = new Date().toISOString(); RES.environment.end_block = await provider.getBlockNumber(); save()
if (lmsProc) lmsProc.stdin.end()
log('\nSummary (gas per record):'); for (const m of RES.measurements.filter(m => m.per_record)) log(`  ${m.design.padEnd(6)} ${m.scheme.padEnd(18)} ${m.per_record}`)
const scan = CHAIN_ID === 11155111n ? 'https://sepolia.etherscan.io/tx/' : ''
if (scan) { log('\nTransactions:'); for (const t of TXS.filter(t => t.hash)) log(`  ${t.label}: ${scan}${t.hash}`) }
log(`\nwritten ${OUT}/sepolia_results.json`); process.exit(0)
