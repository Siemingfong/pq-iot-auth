// Revised harness (major revision): device-signed roots with replay protection, leaf-free and
// leaf-posting variants, on-chain key storage (incl. EIP-8051 expanded keys), PQ-authenticated
// registration, LMS verified for real in Solidity, and an empirical check of the substitution
// method. Osaka rules (EIP-7623 floor, EIP-7825 cap) on the EthereumJS VM.
// Usage: node pq_gasbench2.mjs [--out results2]
import fs from 'node:fs'
import crypto from 'node:crypto'
import { spawn } from 'node:child_process'
import readline from 'node:readline'
import solc from 'solc'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { AbiCoder, Interface } from 'ethers'
import { createVM, runTx } from '@ethereumjs/vm'
import { Common, Hardfork, Mainnet } from '@ethereumjs/common'
import { createFeeMarket1559Tx } from '@ethereumjs/tx'
import { createBlock } from '@ethereumjs/block'
import { Account, Address, hexToBytes, privateToAddress } from '@ethereumjs/util'

const OUT = process.argv.includes('--out') ? process.argv[process.argv.indexOf('--out') + 1] : 'results3'
fs.mkdirSync(OUT, { recursive: true })
const CAP = 16_777_216, CHAIN_ID = 1n, STUB = '0x000000000000000000000000000000000000ab12'
const abi = AbiCoder.defaultAbiCoder()
const S = JSON.parse(fs.readFileSync('pq_samples.json', 'utf8'))
const rnd = (b) => '0x' + crypto.randomBytes(b).toString('hex')
const hex = (u8) => '0x' + Buffer.from(u8).toString('hex')
const kec = (h) => hex(keccak_256(hexToBytes(h)))
const log = (...a) => console.log(...a)

// ------------------------------------------------------------------ verification prices
const V = {
  'ML-DSA-44': { 'Precompile EIP-8355': 6606, 'Solidity, NIST (optimized)': 1_192_929, 'Solidity, EVM-friendly (optimized)': 845_438 },
  'ML-DSA-44 (EIP-8051 key)': { 'Precompile EIP-8051': 4600 },
  'ML-DSA-65': { 'Precompile EIP-8355': 9106 },
  'Falcon-512': { 'Precompile EIP-8052': 3200, 'Solidity, EVM-friendly': 1_547_336 },
  'SLH-DSA-128s': { 'none (data cost only)': 100 },
}
const PK = { 'ML-DSA-44': S['ML-DSA-44'].pk, 'ML-DSA-65': S['ML-DSA-65'].pk, 'Falcon-512': S['Falcon-512'].pk,
  'SLH-DSA-128s': S['SLH-DSA-128s'].pk, 'ML-DSA-44 (EIP-8051 key)': crypto.randomBytes(20512).toString('hex') }
const SIGS = { 'ML-DSA-44': S['ML-DSA-44'].sigs, 'ML-DSA-65': S['ML-DSA-65'].sigs, 'Falcon-512': S['Falcon-512'].sigs,
  'SLH-DSA-128s': S['SLH-DSA-128s'].sigs, 'ML-DSA-44 (EIP-8051 key)': S['ML-DSA-44'].sigs }
let sc = 0
const pqSig = (s) => '0x' + SIGS[s][(sc++) % SIGS[s].length]

// ------------------------------------------------------------------ LMS signing service
const lmsProc = spawn('python3', ['lms_signer.py'], { stdio: ['pipe', 'pipe', 'inherit'] })
const lmsLines = readline.createInterface({ input: lmsProc.stdout })
const lmsQueue = []
lmsLines.on('line', (l) => lmsQueue.shift()(JSON.parse(l)))
const lmsCall = (req) => new Promise((res) => { lmsQueue.push(res); lmsProc.stdin.write(JSON.stringify(req) + '\n') })
const LMS = ['LMS-H10-W2', 'LMS-H10-W4', 'LMS-H10-W8', 'LMS-H15-W4', 'LMS-HSS-H10W4x2']
const lmsKey = (s) => s.slice(4)
const lmsW = (s) => s.split('-')[2]

// ------------------------------------------------------------------ compile & EVM
const srcs = { 'PQAnchor3.sol': { content: fs.readFileSync('PQAnchor3.sol', 'utf8') }, 'LMSVerifier2.sol': { content: fs.readFileSync('LMSVerifier2.sol', 'utf8') } }
const out = JSON.parse(solc.compile(JSON.stringify({ language: 'Solidity', sources: srcs,
  settings: { optimizer: { enabled: true, runs: 200 }, viaIR: true, evmVersion: 'cancun', outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } } })))
const errs = (out.errors || []).filter(e => e.severity === 'error')
if (errs.length) { console.error(errs.map(e => e.formattedMessage).join('\n')); process.exit(1) }
const C = { anchor: out.contracts['PQAnchor3.sol'].PQAnchor3, lms: out.contracts['LMSVerifier2.sol'].LMSVerifier2, meter: out.contracts['LMSVerifier2.sol'].Meter }
const iA = new Interface(C.anchor.abi), iM = new Interface(C.meter.abi)

const common = new Common({ chain: Mainnet, hardfork: Hardfork.Osaka })
const vm = await createVM({ common })
const pkey = hexToBytes('0x' + '55'.repeat(32)), sender = new Address(privateToAddress(pkey))
await vm.stateManager.putAccount(sender, new Account(0n, 10n ** 30n))
const block = createBlock({ header: { number: 23_000_000n, gasLimit: 60_000_000n, baseFeePerGas: 1n, timestamp: 1_780_000_000n } }, { common })
function tokens(d) { let z = 0, nz = 0; for (const b of d) (b === 0 ? z++ : nz++); return { z, nz, tok: z + 4 * nz } }
const txGas = (exec, d) => { const t = tokens(d); return 21000 + Math.max(4 * t.tok + exec, 10 * t.tok) }
async function send(to, data) {
  const nonce = (await vm.stateManager.getAccount(sender)).nonce
  const tx = createFeeMarket1559Tx({ nonce, to, data, gasLimit: BigInt(CAP), maxFeePerGas: 10n ** 10n, maxPriorityFeePerGas: 1n }, { common }).sign(pkey)
  try {
    const r = await runTx(vm, { tx, block, skipBlockGasLimitValidation: true, skipHardForkValidation: true })
    return { ok: r.execResult.exceptionError === undefined, total: Number(r.totalGasSpent), exec: Number(r.execResult.executionGasUsed), addr: r.createdAddress, data, err: r.execResult.exceptionError?.error }
  } catch (e) { if (String(e.message).includes('INTRINSIC_GAS_TOO_LOW')) return { ok: false, invalid: true, data }; throw e }
}
async function deploy(c, args = '') { const r = await send(undefined, hexToBytes('0x' + c.evm.bytecode.object + args)); if (!r.ok) throw new Error('deploy ' + r.err); return r }
const lmsDep = await deploy(C.lms), meterDep = await deploy(C.meter)
const enc = (a) => abi.encode(['address'], [a]).slice(2)
const stubA = (await deploy(C.anchor, enc(STUB))).addr
const lmsA = (await deploy(C.anchor, enc(lmsDep.addr.toString()))).addr
log('deployed; anchor', (await send(undefined, hexToBytes('0x' + C.anchor.evm.bytecode.object + enc(STUB)))).total)

// ------------------------------------------------------------------ devices
const res = { environment: { evm: '@ethereumjs/vm 10.1.3', hardfork: 'osaka', solc: solc.version(), chain_id: 1, verify_gas: V },
  registration: [], dr: [], validation: {}, max_devices: [], check: { diff_max: 0, runs: 0 } }
let nextIdx = 0
const dev = {}           // scheme|variant -> [{idx, pk, commit, sk?}]
const epoch = new Map()  // anchorAddr:idx -> last epoch
const ep = (a, i) => epoch.get(a + ':' + i) || 0
async function register(anchor, key, scheme, m, mode) {   // mode: 'calldata' | 'code'
  dev[key] = dev[key] || []
  for (let j = dev[key].length; j < m; j++) {
    let d
    if (scheme === 'ECDSA') { const sk = secp256k1.utils.randomSecretKey(); d = { sk, pk: hex(keccak_256(secp256k1.getPublicKey(sk, false).slice(1)).slice(12)) } }
    else if (LMS.includes(scheme)) d = { pk: '0x' + (await lmsCall({ key: lmsKey(scheme), pk: true })).pk }
    else d = { pk: '0x' + PK[scheme] }
    d.idx = nextIdx++; d.commit = kec(d.pk)
    const fn = mode === 'code' ? 'registerDeviceCode' : 'registerDevice'
    const r = await send(anchor, hexToBytes(iA.encodeFunctionData(fn, [d.idx, d.pk])))
    if (!r.ok) throw new Error('register ' + scheme + ' ' + r.err)
    d.reg = r.total; dev[key].push(d)
  }
  return dev[key]
}

// ------------------------------------------------------------------ batches
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
    else if (LMS.includes(scheme)) sig = '0x' + (await lmsCall({ key: lmsKey(scheme), msg: m.slice(2) })).sig
    else sig = pqSig(scheme)
    entries.push({ d, e, row: [d.idx, keyOnChain ? '0x' : d.pk, sig, e, root, k, lv] })
  }
  return { data: hexToBytes(iA.encodeFunctionData('submit', [entries.map(x => x.row)])), entries }
}
async function run(anchor, scheme, ds, k, opt) {
  const b = await batch(anchor, scheme, ds, k, opt)
  const r = await send(anchor, b.data)
  if (r.ok) for (const x of b.entries) epoch.set(anchor + ':' + x.d.idx, x.e)
  if (r.ok && anchor === stubA && scheme !== 'ECDSA') { res.check.diff_max = Math.max(res.check.diff_max, Math.abs(txGas(r.exec, b.data) - r.total)); res.check.runs++ }
  return r
}
function price(r, scheme, nVerify, vGas) {
  const t = tokens(r.data)
  if (scheme === 'ECDSA' || LMS.includes(scheme)) return { total: r.total, exec: r.exec, z: t.z, nz: t.nz }
  const exec = r.exec - (2600 + 100 * (nVerify - 1)) + nVerify * vGas
  return { total: txGas(exec, r.data), exec, z: t.z, nz: t.nz }
}
const impls = (s) => (s === 'ECDSA' ? { 'ecrecover': 0 } : LMS.includes(s) ? { 'Solidity LMS (real)': 0 } : V[s])


// ================================================================== revision 3 experiments
const R3 = { pr: [], pr_max: [], lms_verify: [], lms_regression: {}, dr0_lms: [] }
const M = 10
// ---------------------------------------------------------------- A. per-record signatures on PQAnchor3
const seq = new Map()
function prRecs(anchor, scheme, d, cnt) {
  const s0 = (seq.get(anchor + ':' + d.idx) || 0) + 1
  return { s0, recs: Array.from({ length: cnt }, (_, i) => ({ ct: rnd(32), ts: BigInt(1_700_000_000 + i), chk: rnd(32), seed: rnd(20) })) }
}
const leafOf = (r) => kec('0x00' + abi.encode(['bytes32', 'uint64', 'bytes32', 'bytes20'], [r.ct, r.ts, r.chk, r.seed]).slice(2))
const prMsg = (anchor, d, sq, leaf) => kec(abi.encode(['uint256', 'address', 'bytes32', 'uint32', 'uint64', 'bytes32'], [CHAIN_ID, anchor.toString(), d.commit, d.idx, sq, leaf]))
async function prRun(anchor, scheme, ds, perDev) {
  const rows = [], upd = []
  for (const d of ds) {
    const { s0, recs } = prRecs(anchor, scheme, d, perDev)
    const rr = []
    for (let i = 0; i < recs.length; i++) {
      const r = recs[i], m = prMsg(anchor, d, s0 + i, leafOf(r))
      let sig
      if (scheme === 'ECDSA') sig = ecdsaSig(d.sk, m)
      else if (LMS.includes(scheme)) sig = '0x' + (await lmsCall({ key: lmsKey(scheme), msg: m.slice(2) })).sig
      else sig = pqSig(scheme)
      rr.push([r.ct, r.ts, r.chk, r.seed, sig])
    }
    rows.push([d.idx, d.pk, s0, rr]); upd.push([d, s0 + perDev - 1])
  }
  const data = hexToBytes(iA.encodeFunctionData('submitPR', [rows]))
  const r = await send(anchor, data)
  if (r.ok) for (const [d, last] of upd) seq.set(anchor + ':' + d.idx, last)
  return r
}
const PRS = ['ECDSA', 'ML-DSA-44', 'ML-DSA-65', 'Falcon-512', 'SLH-DSA-128s', 'LMS-H10-W4']
V['ML-DSA-87'] = { 'Precompile EIP-8355': 13606 }; PK['ML-DSA-87'] = S['ML-DSA-87'].pk; SIGS['ML-DSA-87'] = S['ML-DSA-87'].sigs
V['SLH-DSA-128f'] = { 'none (data cost only)': 100 }; PK['SLH-DSA-128f'] = S['SLH-DSA-128f'].pk; SIGS['SLH-DSA-128f'] = S['SLH-DSA-128f'].sigs
for (const s of [...PRS, 'ML-DSA-87', 'SLH-DSA-128f']) {
  const A = LMS.includes(s) ? lmsA : stubA
  const ds = await register(A, s + '|pr', s, M, 'calldata')
  { const w = await prRun(A, s, ds, 1); if (!w.ok) log('warm-up failed', s) }   // steady state: sequence slots non-zero
  for (const [label, devs, per] of [['individual', ds.slice(0, 1), 1], ['n=50', ds, 5]]) {
    const r = await prRun(A, s, devs, per)
    if (!r.ok) { R3.pr.push({ scheme: s, impl: '-', config: label, gas: null, per_record: null, note: r.invalid ? 'invalid (floor above cap)' : 'out of gas' }); continue }
    for (const [impl, g] of Object.entries(impls(s))) {
      const n = devs.length * per, p = price(r, s, n, g)
      R3.pr.push({ scheme: s, impl, config: label, gas: p.total, per_record: Math.round(p.total / n), fits_cap: p.total <= CAP, zero_bytes: p.z, nonzero_bytes: p.nz, exec: p.exec })
    }
  }
  log('PR done', s)
}
async function prMax(s, g) {
  const A = LMS.includes(s) ? lmsA : stubA
  const ds = dev[s + '|pr']
  const fits = async (n) => { const per = Math.ceil(n / M); const r = await prRun(A, s, ds, per); return r.ok && price(r, s, per * M, g).total <= CAP ? per * M : 0 }
  let lo = 1, hi = s === 'ECDSA' ? 250 : (LMS.includes(s) ? 8 : 60), best = 0
  while (lo <= hi) { const mid = (lo + hi) >> 1; const f = await fits(mid * M); if (f) { best = f; lo = mid + 1 } else hi = mid - 1 }
  return best
}
for (const [s, impl] of [['ECDSA', 'ecrecover'], ['ML-DSA-44', 'Precompile EIP-8355'], ['Falcon-512', 'Precompile EIP-8052'], ['LMS-H10-W4', 'Solidity LMS (real)']]) {
  const g = impls(s)[impl]; const mx = await prMax(s, g); R3.pr_max.push({ scheme: s, impl, max_records_per_tx: mx }); log('PR max', s, impl, mx)
}

lmsProc.stdin.end()
fs.writeFileSync(`${OUT}/pq3_pr_warm.json`, JSON.stringify(R3, null, 2))
log('written', OUT)
process.exit(0)
