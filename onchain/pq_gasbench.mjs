// Gas harness for post-quantum authentication of IoT records on Ethereum (Osaka rules).
//
// Every transaction is executed on the EthereumJS VM with genuine signature and key bytes in
// calldata (pq_samples.json, liboqs 0.16.0). ECDSA is verified for real with ecrecover. PQ
// verification calls go to an empty account (stub) carrying the full EIP-8355-style input, so
// calldata, memory, hashing, registry and anchoring costs are measured; the verification cost of
// each implementation is then added from VERIFY_GAS:
//   - Solidity verifiers: execution gas reproduced with Foundry from the ZKNOX repositories,
//   - precompiles: prices proposed in EIP-8355 (ML-DSA) and EIP-8052 (Falcon-512).
// Transaction gas follows EIP-7623: gasUsed = 21000 + max(4*tokens + execution, 10*tokens),
// tokens = zero_bytes + 4*nonzero_bytes; validated against the VM for every stub run.
//
// Usage: node pq_gasbench.mjs [--quick] [--out results]
import fs from 'node:fs'
import crypto from 'node:crypto'
import solc from 'solc'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { AbiCoder, Interface } from 'ethers'
import { createVM, runTx } from '@ethereumjs/vm'
import { Common, Hardfork, Mainnet } from '@ethereumjs/common'
import { createFeeMarket1559Tx } from '@ethereumjs/tx'
import { createBlock } from '@ethereumjs/block'
import { Account, Address, hexToBytes, privateToAddress } from '@ethereumjs/util'

const QUICK = process.argv.includes('--quick')
const OUT = process.argv.includes('--out') ? process.argv[process.argv.indexOf('--out') + 1] : 'results'
fs.mkdirSync(OUT, { recursive: true })
const CAP = 16_777_216
const STUB = '0x000000000000000000000000000000000000ab12'
const abi = AbiCoder.defaultAbiCoder()
const S = JSON.parse(fs.readFileSync('pq_samples.json', 'utf8'))
const rnd = (b) => '0x' + crypto.randomBytes(b).toString('hex')
const hex = (u8) => '0x' + Buffer.from(u8).toString('hex')
const kec = (h) => hex(keccak_256(hexToBytes(h)))

// ---------------------------------------------------------------- verification gas per call
// Solidity values: Foundry 1.8.7, solc 0.8.30/0.8.25, repository settings (see methodology).
// Precompile values include the 100-gas warm CALL.
const IMPL = {
  'ML-DSA-44': {
    'Solidity, NIST (ZKNOX main)': 8_128_360,
    'Solidity, NIST (ZKNOX optimized)': 1_192_929,
    'Solidity, EVM-friendly (ZKNOX optimized)': 845_438,
    'Precompile EIP-8355': 100 + 6500 + 6,
  },
  'ML-DSA-65': { 'Precompile EIP-8355': 100 + 9000 + 6 },
  'ML-DSA-87': { 'Precompile EIP-8355': 100 + 13500 + 6 },
  'Falcon-512': {
    'Solidity, NIST (ZKNOX)': 4_818_843,
    'Solidity, EVM-friendly (ZKNOX)': 1_547_336,
    'Precompile EIP-8052': 2 * 100 + 1000 + 2000,
  },
  'SLH-DSA-128s': { 'no verifier (data cost only)': 100 },
  'SLH-DSA-128f': { 'no verifier (data cost only)': 100 },
}

// ---------------------------------------------------------------- compile & EVM
const src = fs.readFileSync('PQAnchor.sol', 'utf8')
const out = JSON.parse(solc.compile(JSON.stringify({ language: 'Solidity', sources: { 'PQAnchor.sol': { content: src } },
  settings: { optimizer: { enabled: true, runs: 200 }, viaIR: true, evmVersion: 'cancun',
    outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } } })))
const errs = (out.errors || []).filter(e => e.severity === 'error')
if (errs.length) { console.error(errs.map(e => e.formattedMessage).join('\n')); process.exit(1) }
const C = out.contracts['PQAnchor.sol'].PQAnchor
const iface = new Interface(C.abi)

const common = new Common({ chain: Mainnet, hardfork: Hardfork.Osaka })
const vm = await createVM({ common })
const pkey = hexToBytes('0x' + '44'.repeat(32))
const sender = new Address(privateToAddress(pkey))
await vm.stateManager.putAccount(sender, new Account(0n, 10n ** 30n))
const block = createBlock({ header: { number: 23_000_000n, gasLimit: 60_000_000n, baseFeePerGas: 1n, timestamp: 1_780_000_000n } }, { common })
async function send(to, data, gasLimit = BigInt(CAP)) {
  const nonce = (await vm.stateManager.getAccount(sender)).nonce
  const tx = createFeeMarket1559Tx({ nonce, to, data, gasLimit, maxFeePerGas: 10n ** 10n, maxPriorityFeePerGas: 1n }, { common }).sign(pkey)
  let r
  try { r = await runTx(vm, { tx, block, skipBlockGasLimitValidation: true, skipHardForkValidation: true }) }
  catch (e) {   // e.g. EIP-7623 calldata floor alone exceeds the EIP-7825 cap: the transaction is invalid
    if (String(e.message).includes('INTRINSIC_GAS_TOO_LOW')) return { ok: false, invalid: true, err: 'intrinsic gas above cap', data }
    throw e
  }
  return { total: Number(r.totalGasSpent), exec: Number(r.execResult.executionGasUsed), ok: r.execResult.exceptionError === undefined,
           err: r.execResult.exceptionError?.error, addr: r.createdAddress, data }
}
function tokens(data) { let z = 0, nz = 0; for (const b of data) (b === 0 ? z++ : nz++); return { z, nz, tok: z + 4 * nz } }
function txGas(execution, data) { const t = tokens(data); return 21000 + Math.max(4 * t.tok + execution, 10 * t.tok) }

const deployData = hexToBytes('0x' + C.evm.bytecode.object + abi.encode(['address'], [STUB]).slice(2))
const dep = await send(undefined, deployData)
if (!dep.ok) throw new Error('deploy ' + dep.err)
const A = dep.addr
console.log('deployed PQAnchor, gas', dep.total)

// ---------------------------------------------------------------- devices
const M = 10
let nextIdx = 0
const devices = {}
async function register(scheme, m) {
  devices[scheme] = []
  for (let j = 0; j < m; j++) {
    let d
    if (scheme === 'ECDSA') {
      const sk = secp256k1.utils.randomSecretKey()
      const addr = hex(keccak_256(secp256k1.getPublicKey(sk, false).slice(1)).slice(12))
      d = { sk, pk: addr }
    } else d = { pk: '0x' + S[scheme].pk }
    d.idx = nextIdx++
    d.commit = kec(d.pk)
    const r = await send(A, hexToBytes(iface.encodeFunctionData('registerDevice', [d.idx, d.pk])))
    if (!r.ok) throw new Error('register ' + r.err)
    d.regGas = r.total
    devices[scheme].push(d)
  }
}
function ecdsaSig(sk, h) {
  const s = secp256k1.Signature.fromBytes(secp256k1.sign(hexToBytes(h), sk, { prehash: false, format: 'recovered' }), 'recovered')
  return '0x' + s.r.toString(16).padStart(64, '0') + s.s.toString(16).padStart(64, '0') + (27 + s.recovery).toString(16)
}
let sigCursor = 0
const pqSig = (scheme) => { const a = S[scheme].sigs; return '0x' + a[(sigCursor++) % a.length] }
function merkle(h) {   // identical to PQAnchor._merkle
  let l = h.slice()
  while (l.length > 1) { const n = []; for (let i = 0; i < l.length; i += 2) n.push(i + 1 < l.length ? kec(l[i] + l[i + 1].slice(2)) : l[i]); l = n }
  return l[0]
}

// ---------------------------------------------------------------- transaction builders
function record(i) { return { ct: rnd(32), ts: BigInt(1_700_000_000 + i), chk: rnd(32), seed: rnd(20) } }
function recHash(c, r) { return kec(abi.encode(['address', 'bytes32', 'bytes32', 'uint64', 'bytes32', 'bytes20'], [A.toString(), c, r.ct, r.ts, r.chk, r.seed])) }
function prData(scheme, n) {
  const m = Math.min(n, M), ds = devices[scheme].slice(0, m)
  const recs = []
  for (let i = 0; i < n; i++) {
    const j = i % m, r = record(i)
    const sig = scheme === 'ECDSA' ? ecdsaSig(ds[j].sk, recHash(ds[j].commit, r)) : pqSig(scheme)
    recs.push([j, r.ct, r.ts, r.chk, r.seed, sig])
  }
  return hexToBytes(iface.encodeFunctionData('submitPerRecord', [ds.map(d => [d.idx, d.pk]), recs]))
}
function oneData(scheme) {
  const d = devices[scheme][0], r = record(0)
  const sig = scheme === 'ECDSA' ? ecdsaSig(d.sk, recHash(d.commit, r)) : pqSig(scheme)
  return hexToBytes(iface.encodeFunctionData('submitOne', [[d.idx, d.pk], [0, r.ct, r.ts, r.chk, r.seed, sig]]))
}
function drData(scheme, m, k) {
  const bs = []
  for (let j = 0; j < m; j++) {
    const d = devices[scheme][j % devices[scheme].length]
    const leaves = Array.from({ length: k }, () => rnd(32))
    let sig
    if (scheme === 'ECDSA') sig = ecdsaSig(d.sk, kec(abi.encode(['address', 'bytes32', 'bytes32'], [A.toString(), d.commit, merkle(leaves)])))
    else sig = pqSig(scheme)
    bs.push([d.idx, d.pk, sig, leaves])
  }
  return hexToBytes(iface.encodeFunctionData('submitDeviceRoots', [bs]))
}

// ---------------------------------------------------------------- evaluation
const check = { predicted_vs_vm_max_abs_diff: 0, runs: 0 }
async function measure(data, nVerify, scheme) {
  const r = await send(A, data)
  if (!r.ok) return null   // reverted (out of gas under the cap) or invalid (calldata floor above the cap)
  if (scheme !== 'ECDSA') {                         // validate the EIP-7623 formula on the stub run
    const diff = Math.abs(txGas(r.exec, data) - r.total)
    check.predicted_vs_vm_max_abs_diff = Math.max(check.predicted_vs_vm_max_abs_diff, diff); check.runs++
  }
  return { exec: r.exec, data, total: r.total, nVerify }
}
function priced(m, scheme, implGas) {           // replace stub calls by the implementation's verification gas
  if (scheme === 'ECDSA') { const t = tokens(m.data); return { total: m.total, exec: m.exec, tok: t.tok, stdCalldata: 4 * t.tok, floor: 10 * t.tok } }
  const stub = 2600 + 100 * (m.nVerify - 1)
  const exec = m.exec - stub + m.nVerify * implGas
  const t = tokens(m.data)
  return { total: txGas(exec, m.data), exec, tok: t.tok, stdCalldata: 4 * t.tok, floor: 10 * t.tok }
}
const impls = (scheme) => scheme === 'ECDSA' ? { 'ecrecover (real)': 0 } : IMPL[scheme]

const SCHEMES = ['ECDSA', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'Falcon-512', 'SLH-DSA-128s', 'SLH-DSA-128f']
const res = { environment: { evm: '@ethereumjs/vm 10.1.3', hardfork: 'osaka', solc: solc.version(), tx_gas_cap: CAP,
  devices_per_batch: M, verify_gas: IMPL }, deploy_gas: dep.total, register_gas: {}, individual: [], per_record: [], device_root: [], max_batch: [], check }

for (const sc of SCHEMES) { await register(sc, M); res.register_gas[sc] = devices[sc][1].regGas }

// ---- individual submission (one record per transaction)
for (const sc of SCHEMES) {
  const m = await measure(oneData(sc), 1, sc)
  for (const [impl, g] of Object.entries(impls(sc))) {
    const p = priced(m, sc, g)
    res.individual.push({ scheme: sc, impl, gas: p.total, calldata_bytes: m.data.length })
  }
}
console.log('individual done')

// ---- PR: per-record signatures in batches
const NS = QUICK ? [1, 10] : [1, 10, 50, 100, 200]
for (const sc of SCHEMES) for (const n of NS) {
  const m = await measure(prData(sc, n), n, sc)
  if (!m) { console.log(`PR ${sc} n=${n} stub run failed (cap)`); continue }
  for (const [impl, g] of Object.entries(impls(sc))) {
    const p = priced(m, sc, g)
    res.per_record.push({ scheme: sc, impl, n, gas: p.total, per_record: Math.round(p.total / n),
      fits_cap: p.total <= CAP, calldata_per_record: Math.round(m.data.length / n), floor_binding: p.total === 21000 + 10 * tokens(m.data).tok,
      execution: p.exec, calldata_standard: p.stdCalldata, calldata_floor: p.floor })
  }
}
console.log('per-record done')

// ---- DR: device-signed Merkle roots, m devices x k records
const KS = QUICK ? [1, 10] : [1, 10, 100, 1000]
for (const sc of SCHEMES) for (const k of KS) {
  const m = await measure(drData(sc, M, k), M, sc)
  if (!m) { console.log(`DR ${sc} k=${k} stub failed`); continue }
  for (const [impl, g] of Object.entries(impls(sc))) {
    const p = priced(m, sc, g)
    res.device_root.push({ scheme: sc, impl, devices: M, k, n: M * k, gas: p.total, per_record: Math.round(p.total / (M * k)),
      fits_cap: p.total <= CAP, floor_binding: p.total === 21000 + 10 * tokens(m.data).tok,
      execution: p.exec, calldata_standard: p.stdCalldata, calldata_floor: p.floor })
  }
  console.log(`DR ${sc} k=${k} done`)
}

// ---- largest batch under the per-transaction cap (bisection on actual stub runs + pricing)
async function maxFit(build, nVerifyOf, sc, g, lo, hi) {
  const fits = async (x) => { const m = await measure(build(x), nVerifyOf(x), sc); return m && priced(m, sc, g).total <= CAP }
  if (!(await fits(lo))) return 0
  while (hi - lo > Math.max(1, Math.floor(lo * 0.01))) { const mid = Math.floor((lo + hi) / 2); if (await fits(mid)) lo = mid; else hi = mid }
  return lo
}
if (!QUICK) {
  for (const sc of SCHEMES) for (const [impl, g] of Object.entries(impls(sc))) {
    const pr = await maxFit((n) => prData(sc, n), (n) => n, sc, g, 1, 3000)
    // device-root with k = 100 records per device: how many devices fit in one transaction
    const dr = await maxFit((m) => drData(sc, m, 100), (m) => m, sc, g, 1, 200)
    res.max_batch.push({ scheme: sc, impl, per_record_max_records: pr, device_root_k100_max_devices: dr, device_root_k100_max_records: dr * 100 })
    console.log(`max ${sc} | ${impl}: PR ${pr} records, DR(k=100) ${dr} devices`)
  }
}

fs.writeFileSync(`${OUT}/pq_gas_results.json`, JSON.stringify(res, null, 2))
const csv = (rows) => [Object.keys(rows[0]).join(','), ...rows.map(r => Object.values(r).map(v => typeof v === 'string' && v.includes(',') ? `"${v}"` : v).join(','))].join('\n') + '\n'
for (const k of ['individual', 'per_record', 'device_root', 'max_batch']) if (res[k].length) fs.writeFileSync(`${OUT}/pq_${k}.csv`, csv(res[k]))
console.log('formula check:', JSON.stringify(check))
console.log('written to', OUT)
