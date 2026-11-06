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
import { p256 } from '@noble/curves/nist.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { AbiCoder, Interface } from 'ethers'
import { createVM, runTx } from '@ethereumjs/vm'
import { Common, Hardfork, Mainnet } from '@ethereumjs/common'
import { createFeeMarket1559Tx } from '@ethereumjs/tx'
import { createBlock } from '@ethereumjs/block'
import { Account, Address, hexToBytes, privateToAddress } from '@ethereumjs/util'

const OUT = 'results8'
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
// P-256 (EIP-7951, live in Osaka) and hybrid ECDSA + PQ, priced by substitution (verification gas incl. 100-gas calls)
V['P-256'] = { 'Precompile EIP-7951': 6900 + 100 }; PK['P-256'] = crypto.randomBytes(64).toString('hex'); SIGS['P-256'] = Array.from({ length: 20 }, () => crypto.randomBytes(64).toString('hex'))
V['Hybrid ML-DSA-44 + ECDSA'] = { 'EIP-8355 + ecrecover': 6606 + 3100 }; PK['Hybrid ML-DSA-44 + ECDSA'] = S['ML-DSA-44'].pk + crypto.randomBytes(20).toString('hex'); SIGS['Hybrid ML-DSA-44 + ECDSA'] = S['ML-DSA-44'].sigs.map(x => x + crypto.randomBytes(65).toString('hex'))
V['Hybrid Falcon-512 + ECDSA'] = { 'EIP-8052 + ecrecover': 3200 + 3100 }; PK['Hybrid Falcon-512 + ECDSA'] = S['Falcon-512'].pk + crypto.randomBytes(20).toString('hex'); SIGS['Hybrid Falcon-512 + ECDSA'] = S['Falcon-512'].sigs.map(x => x + crypto.randomBytes(65).toString('hex'))
let sc = 0
const pqSig = (s) => '0x' + SIGS[s][(sc++) % SIGS[s].length]

// ------------------------------------------------------------------ LMS signing service
const lmsProc = spawn('python3', ['lms_signer.py'], { stdio: ['pipe', 'pipe', 'inherit'] })
const lmsLines = readline.createInterface({ input: lmsProc.stdout })
const lmsQueue = []
lmsLines.on('line', (l) => lmsQueue.shift()(JSON.parse(l)))
const lmsCall = (req) => new Promise((res) => { lmsQueue.push(res); lmsProc.stdin.write(JSON.stringify(req) + '\n') })
const LMS = ['LMS-H10-W2', 'LMS-H10-W4', 'LMS-H10-W8', 'LMS-H15-W4', 'LMS-HSS-H10W4x2', 'LMS-M24-H10-W4', 'LMS-HSS-M24-H10W4x2']
const lmsKey = (s) => s.slice(4)
const lmsW = (s) => s.split('-')[2]

// ------------------------------------------------------------------ compile & EVM
const srcs = { 'PQAnchor5.sol': { content: fs.readFileSync('PQAnchor5.sol', 'utf8') }, 'LMSVerifier2.sol': { content: fs.readFileSync('LMSVerifier2.sol', 'utf8') }, 'LMSVerifier3.sol': { content: fs.readFileSync('LMSVerifier3.sol', 'utf8') } }
const out = JSON.parse(solc.compile(JSON.stringify({ language: 'Solidity', sources: srcs,
  settings: { optimizer: { enabled: true, runs: 200 }, viaIR: true, evmVersion: 'cancun', outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } } })))
const errs = (out.errors || []).filter(e => e.severity === 'error')
if (errs.length) { console.error(errs.map(e => e.formattedMessage).join('\n')); process.exit(1) }
const C = { anchor: out.contracts['PQAnchor5.sol'].PQAnchor5, lms: out.contracts['LMSVerifier2.sol'].LMSVerifier2, meter: out.contracts['LMSVerifier2.sol'].Meter }
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
    return { ok: r.execResult.exceptionError === undefined, total: Number(r.totalGasSpent), exec: Number(r.execResult.executionGasUsed), addr: r.createdAddress, data, err: r.execResult.exceptionError?.error, logs: r.receipt?.logs || r.execResult.logs || [] }
  } catch (e) { if (String(e.message).includes('INTRINSIC_GAS_TOO_LOW')) return { ok: false, invalid: true, data }; throw e }
}
async function deploy(c, args = '') { const r = await send(undefined, hexToBytes('0x' + c.evm.bytecode.object + args)); if (!r.ok) throw new Error('deploy ' + r.err); return r }
const lmsDep = await deploy(C.lms), meterDep = await deploy(C.meter)
const enc = (a, w = true) => abi.encode(['address', 'bool'], [a, w]).slice(2)
const stubA = (await deploy(C.anchor, enc(STUB))).addr
const lmsA = (await deploy(C.anchor, enc(lmsDep.addr.toString()))).addr
const lms3Dep = await deploy(out.contracts['LMSVerifier3.sol'].LMSVerifier3)
const lms3A = (await deploy(C.anchor, enc(lms3Dep.addr.toString()))).addr
const stubS = (await deploy(C.anchor, enc(STUB, false))).addr
const lmsS = (await deploy(C.anchor, enc(lmsDep.addr.toString(), false))).addr
log('deployed')

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
    else if (scheme === 'P-256') { const sk = p256.utils.randomSecretKey(); d = { sk, pk: hex(p256.getPublicKey(sk, false).slice(1)) } }
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
    else if (scheme === 'P-256') sig = hex(p256.sign(hexToBytes(m), d.sk, { prehash: false, format: 'compact' }))
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
  if (scheme === 'ECDSA' || scheme === 'P-256' || LMS.includes(scheme)) return { total: r.total, exec: r.exec, z: t.z, nz: t.nz }
  const exec = r.exec - (2600 + 100 * (nVerify - 1)) + nVerify * vGas
  return { total: txGas(exec, r.data), exec, z: t.z, nz: t.nz }
}
const impls = (s) => (s === 'ECDSA' ? { 'ecrecover': 0 } : s === 'P-256' ? { 'EIP-7951 (executed)': 0 } : LMS.includes(s) ? { 'Solidity LMS (real)': 0 } : V[s])



V['ML-DSA-87'] = { 'Precompile EIP-8355': 13606 }; PK['ML-DSA-87'] = S['ML-DSA-87'].pk; SIGS['ML-DSA-87'] = S['ML-DSA-87'].sigs
const anchorOf = (s, strict = false) => (s === 'LMS-M24-H10-W4' || s === 'LMS-HSS-M24-H10W4x2') ? lms3A : (LMS.includes(s) ? (strict ? lmsS : lmsA) : (strict ? stubS : stubA))
const R5 = { encoding: [], epoch: {}, noverify: [], model: [], lms_stats: [], grind: [] }
const M = 10
const hexs = (x) => x.startsWith('0x') ? x.slice(2) : x
const be = (v, b) => BigInt(v).toString(16).padStart(2 * b, '0')
const glam = (r) => { const t = tokens(r.data); return 21000 + Math.max(4 * t.tok + r.execP, 64 * (t.z + t.nz)) }
async function sigFor(scheme, d, m) {
  if (scheme === 'ECDSA') return ecdsaSig(d.sk, m)
  if (scheme === 'P-256') return hex(p256.sign(hexToBytes(m), d.sk, { prehash: false, format: 'compact' }))
  if (LMS.includes(scheme)) return '0x' + (await lmsCall({ key: lmsKey(scheme), msg: m.slice(2) })).sig
  return pqSig(scheme)
}
// ---- packed device-root transaction (op 0x01)
async function packedDR(A, scheme, ds, k, { leaves, keyOnChain, mode = 0 }) {
  let hx = '01' + be(mode, 1) + be(ds.length, 2); const upd = []
  for (const d of ds) {
    const e = ep(A, d.idx) + 1, lv = leaves ? Array.from({ length: k }, () => rnd(32)) : [], root = leaves ? merkle(lv) : rnd(32)
    let sig = mode === 2 ? rnd(32) : await sigFor(scheme, d, msgOf(A, d, e, root, k))
    hx += be(d.idx, 4) + be(e, 8) + be(k, 4) + be((leaves ? 1 : 0) | (keyOnChain ? 2 : 0), 1)
    if (!leaves) hx += hexs(root)
    if (!keyOnChain) hx += be(hexs(d.pk).length / 2, 2) + hexs(d.pk)
    hx += be(hexs(sig).length / 2, 2) + hexs(sig) + lv.map(hexs).join('')
    upd.push([d, e])
  }
  const r = await send(A, hexToBytes('0x' + hx))
  if (r.ok) for (const [d, e] of upd) epoch.set(A + ':' + d.idx, e)
  return r
}
// ---- packed per-record transaction (op 0x02)
const seqm = new Map()
async function packedPR(A, scheme, ds, per) {
  let hx = '02' + be(ds.length, 2) + be(ds.length * per, 4); const upd = []
  for (const d of ds) {
    const s0 = (seqm.get(A + ':' + d.idx) || 0) + 1
    hx += be(d.idx, 4) + be(s0, 8) + be(per, 2) + be(hexs(d.pk).length / 2, 2) + hexs(d.pk)
    for (let i = 0; i < per; i++) {
      const rec = { ct: rnd(32), ts: BigInt(1_700_000_000 + i), chk: rnd(32), seed: rnd(20) }
      const leaf = kec('0x00' + abi.encode(['bytes32', 'uint64', 'bytes32', 'bytes20'], [rec.ct, rec.ts, rec.chk, rec.seed]).slice(2))
      const m = kec(abi.encode(['uint256', 'address', 'bytes32', 'uint32', 'uint64', 'bytes32'], [CHAIN_ID, A.toString(), d.commit, d.idx, s0 + i, leaf]))
      const sig = await sigFor(scheme, d, m)
      hx += hexs(rec.ct) + be(rec.ts, 8) + hexs(rec.chk) + hexs(rec.seed) + be(hexs(sig).length / 2, 2) + hexs(sig)
    }
    upd.push([d, s0 + per - 1])
  }
  const r = await send(A, hexToBytes('0x' + hx))
  if (r.ok) for (const [d, l] of upd) seqm.set(A + ':' + d.idx, l)
  return r
}
// ---- ABI per-record transaction (submitPR), sequence numbers tracked separately
const seqa = seqm
async function abiPR(A, scheme, ds, per) {
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
  const r = await send(A, hexToBytes(iA.encodeFunctionData('submitPR', [rows])))
  if (r.ok) for (const [d, l] of upd) seqa.set(A + ':' + d.idx, l)
  return r
}
const REJ = kec('0x' + Buffer.from('DeviceRejected(uint32,uint64)').toString('hex'))
const rejected = (r) => (r.logs || []).filter(l => '0x' + Buffer.from(l[1][0]).toString('hex') === REJ).length
function rec(design, enc, s, impl, r, nRec, nVer, g) {
  const nr = rejected(r); if (nr > 0) throw new Error(`${design} ${enc} ${s}: ${nr} rejected`)
  const p = price(r, s, nVer, g), t = tokens(r.data)
  const row = { design, encoding: enc, scheme: s, impl, ok: r.ok, records: nRec, tx_gas: p.total, per_record: Math.round(p.total / nRec),
    bytes_per_record: +((t.z + t.nz) / nRec).toFixed(1), zero_fraction: +(t.z / (t.z + t.nz)).toFixed(3),
    glamsterdam_per_record: Math.round(glam({ data: r.data, execP: p.exec }) / nRec) }
  R5.encoding.push(row); return row
}
// ================================================================= A. ABI vs packed encoding
for (const s of ['ECDSA', 'P-256', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'Falcon-512', 'LMS-H10-W4', 'LMS-HSS-H10W4x2', 'LMS-HSS-M24-H10W4x2']) {
  const A = anchorOf(s)
  const dsC = await register(A, s + '|enc|cd', s, M, 'calldata')
  const dsK = LMS.includes(s) ? null : await register(A, s + '|enc|code', s, M, 'code')
  await run(A, s, dsC, 1, { leaves: false, keyOnChain: false }); if (dsK) await run(A, s, dsK, 1, { leaves: false, keyOnChain: true })
  await abiPR(A, s, dsC, 1); await packedPR(A, s, dsC, 1)               // warm the sequence slots
  for (const [impl, g] of Object.entries(impls(s))) {
    if (impl.startsWith('Solidity') && !LMS.includes(s)) continue
    const go = async (design, enc, fn, nRec, nVer) => { const r = await fn(); if (!r.ok) { log('FAILED', design, enc, s, r.err); return } const x = rec(design, enc, s, impl, r, nRec, nVer, g); log(design, enc, s, impl, x.per_record, x.bytes_per_record, x.zero_fraction) }
    await go('PR n=50', 'ABI', () => abiPR(A, s, dsC, 5), 50, 50)
    await go('PR n=50', 'packed', () => packedPR(A, s, dsC, 5), 50, 50)
    await go('DR-L k=100', 'ABI', () => run(A, s, dsC, 100, { leaves: true, keyOnChain: false }), 1000, M)
    await go('DR-L k=100', 'packed', () => packedDR(A, s, dsC, 100, { leaves: true, keyOnChain: false }), 1000, M)
    await go('DR-0 k=100', 'ABI', () => run(A, s, dsC, 100, { leaves: false, keyOnChain: false }), 1000, M)
    await go('DR-0 k=100', 'packed', () => packedDR(A, s, dsC, 100, { leaves: false, keyOnChain: false }), 1000, M)
    if (dsK) {
      await go('DR-0C k=100', 'ABI', () => run(A, s, dsK, 100, { leaves: false, keyOnChain: true }), 1000, M)
      await go('DR-0C k=100', 'packed', () => packedDR(A, s, dsK, 100, { leaves: false, keyOnChain: true }), 1000, M)
    }
  }
}

// ================================================================= recommended long-lived LMS configurations
for (const s of ['LMS-H15-W4', 'LMS-HSS-H10W4x2', 'LMS-HSS-M24-H10W4x2']) {
  const A = anchorOf(s)
  for (const kc of [false, true]) {
    const ds = await register(A, `${s}|lt|${kc}`, s, M, kc ? 'code' : 'calldata')
    await run(A, s, ds, 1, { leaves: false, keyOnChain: kc })
    const r = await run(A, s, ds, 1, { leaves: false, keyOnChain: kc })
    if (rejected(r)) throw new Error('rejected ' + s)
    R5.encoding.push({ design: kc ? 'DR-0C k=100' : 'DR-0 k=100', encoding: 'ABI', scheme: s, impl: 'Solidity LMS (real)', ok: r.ok, records: 1000, tx_gas: r.total, per_record: Math.round(r.total / 1000), per_device: Math.round(r.total / M) })
    log('long-lived', s, kc ? 'DR-0C' : 'DR-0', Math.round(r.total / 1000))
  }
}
// ================================================================= registration and revocation
const REG = []
{
  const kh = (x) => kec(x)
  for (const [s, key] of [['ML-DSA-44', PK['ML-DSA-44']], ['ML-DSA-65', PK['ML-DSA-65']], ['Falcon-512', PK['Falcon-512']], ['ML-DSA-44 (EIP-8051 key)', PK['ML-DSA-44 (EIP-8051 key)']]]) {
    for (const fn of ['registerDevice', 'registerDeviceCode']) { const r = await send(stubA, hexToBytes(iA.encodeFunctionData(fn, [nextIdx++, '0x' + key]))); REG.push({ scheme: s, op: fn, gas: r.total, ok: r.ok }) }
  }
  // PQ-authorized registration and revocation, RA key = ML-DSA-44 (priced) on the stub anchor
  await send(stubA, hexToBytes(iA.encodeFunctionData('setRaPqKey', ['0x' + PK['ML-DSA-44']])))
  const idx = nextIdx++
  const r1 = await send(stubA, hexToBytes(iA.encodeFunctionData('registerDevicePQ', [idx, '0x' + PK['ML-DSA-44'], pqSig('ML-DSA-44')])))
  const r2 = await send(stubA, hexToBytes(iA.encodeFunctionData('revokeDevicePQ', [idx, pqSig('ML-DSA-44')])))
  for (const [impl, g] of Object.entries(V['ML-DSA-44'])) { REG.push({ scheme: 'RA ML-DSA-44', op: 'registerDevicePQ ' + impl, gas: price(r1, 'x', 1, g).total, ok: r1.ok }); REG.push({ scheme: 'RA ML-DSA-44', op: 'revokeDevicePQ ' + impl, gas: price(r2, 'x', 1, g).total, ok: r2.ok }) }
  // RA key = two-level HSS (n = 32), verified for real
  const raPk = '0x' + (await lmsCall({ key: 'HSS-H10W4x2', pk: true })).pk
  await send(lmsA, hexToBytes(iA.encodeFunctionData('setRaPqKey', [raPk])))
  const dpk = '0x' + (await lmsCall({ key: 'H10-W4', pk: true })).pk
  for (const fn of ['registerDevice', 'registerDeviceCode']) { const r = await send(lmsA, hexToBytes(iA.encodeFunctionData(fn, [nextIdx++, dpk]))); REG.push({ scheme: 'LMS-H10-W4', op: fn, gas: r.total, ok: r.ok }) }
  const j = nextIdx++
  const mReg = kec(abi.encode(['uint256', 'address', 'string', 'uint32', 'bytes32', 'uint64'], [CHAIN_ID, lmsA.toString(), 'register', j, kh(dpk), 0]))
  const r3 = await send(lmsA, hexToBytes(iA.encodeFunctionData('registerDevicePQ', [j, dpk, '0x' + (await lmsCall({ key: 'HSS-H10W4x2', msg: mReg.slice(2) })).sig])))
  const mRev = kec(abi.encode(['uint256', 'address', 'string', 'uint32', 'bytes32', 'uint64'], [CHAIN_ID, lmsA.toString(), 'revoke', j, kh(dpk), 1]))
  const r4 = await send(lmsA, hexToBytes(iA.encodeFunctionData('revokeDevicePQ', [j, '0x' + (await lmsCall({ key: 'HSS-H10W4x2', msg: mRev.slice(2) })).sig])))
  REG.push({ scheme: 'RA HSS (H10-W4)^2', op: 'registerDevicePQ (real)', gas: r3.total, ok: r3.ok }, { scheme: 'RA HSS (H10-W4)^2', op: 'revokeDevicePQ (real)', gas: r4.total, ok: r4.ok })
  log('registration', JSON.stringify(REG))
}
// ================================================================= epoch rule and reordering
const EP = {}
{
  for (const [name, A] of [['strict', stubS], ['window', stubA]]) {
    const ds = await register(A, 'ECDSA|ep|' + name, 'ECDSA', M, 'calldata')
    await packedDR(A, 'ECDSA', ds, 1, { leaves: false, keyOnChain: false })
    const r = await packedDR(A, 'ECDSA', ds, 1, { leaves: false, keyOnChain: false }); if (rejected(r)) throw new Error('ep')
    EP[name + '_per_device'] = Math.round(r.total / M)
    const d = (await register(A, 'ECDSA|ro|' + name, 'ECDSA', 1, 'calldata'))[0]
    await packedDR(A, 'ECDSA', [d], 1, { leaves: false, keyOnChain: false })
    const e1 = ep(A, d.idx)
    epoch.set(A + ':' + d.idx, e1 + 1); await packedDR(A, 'ECDSA', [d], 1, { leaves: false, keyOnChain: false })
    epoch.set(A + ':' + d.idx, e1); const late = await packedDR(A, 'ECDSA', [d], 1, { leaves: false, keyOnChain: false })
    EP[name + '_late_root_accepted'] = rejected(late) === 0
  }
  log('epoch', JSON.stringify(EP))
}
// ================================================================= anchoring without verification (packed, key not loaded)
const NV = []
for (const [label, mode] of [['no verification, ML-DSA-44 signature posted', 1], ['no verification, only H(sig) posted', 2]]) {
  const ds = await register(stubA, 'ML-DSA-44|nv' + mode, 'ML-DSA-44', M, 'code')
  await packedDR(stubA, 'ML-DSA-44', ds, 1, { leaves: false, keyOnChain: true, mode })
  const r = await packedDR(stubA, 'ML-DSA-44', ds, 1, { leaves: false, keyOnChain: true, mode }); if (rejected(r)) throw new Error('nv')
  const t = tokens(r.data)
  NV.push({ label, per_device: Math.round(r.total / M), per_record_k100: Math.round(r.total / (M * 100)), exec: r.exec, bytes: t.z + t.nz, glamsterdam_k100: Math.round(glam({ data: r.data, execP: r.exec }) / (M * 100)) })
}
log('noverify', JSON.stringify(NV))
// ================================================================= model points with exact tokens and execution (DR-L, ABI)
const MP = []
for (const [s, impl] of [['ECDSA', 'ecrecover'], ['ML-DSA-44', 'Precompile EIP-8355'], ['LMS-H10-W4', 'Solidity LMS (real)']]) {
  const g = impls(s)[impl], A = anchorOf(s)
  for (const [m, k] of [[10, 10], [10, 100], [10, 200], [4, 500], [4, 1000], [2, 2000]]) {
    const ds = await register(A, `${s}|mp|${m}`, s, m, 'calldata')
    if (ep(A, ds[0].idx) === 0) await run(A, s, ds, 1, { leaves: false, keyOnChain: false })
    const r = await run(A, s, ds, k, { leaves: true, keyOnChain: false }); if (!r.ok || rejected(r)) throw new Error('model ' + s)
    const p = price(r, s, m, g), t = tokens(r.data)
    MP.push({ scheme: s, m, k, n: m * k, tx_gas: p.total, exec: p.exec, tokens: t.tok, per_record: Math.round(p.total / (m * k)) })
  }
  log('model', s)
}
fs.writeFileSync(`${OUT}/pq8_extras.json`, JSON.stringify({ encoding: R5.encoding, registration: REG, epoch: EP, noverify: NV, model: MP }, null, 2))

lmsProc.stdin.end()
log('written'); process.exit(0)
