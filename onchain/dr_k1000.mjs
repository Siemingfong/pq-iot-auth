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
import { keccak_256 } from '@noble/hashes/sha3.js'
import { AbiCoder, Interface } from 'ethers'
import { createVM, runTx } from '@ethereumjs/vm'
import { Common, Hardfork, Mainnet } from '@ethereumjs/common'
import { createFeeMarket1559Tx } from '@ethereumjs/tx'
import { createBlock } from '@ethereumjs/block'
import { Account, Address, hexToBytes, privateToAddress } from '@ethereumjs/util'

const OUT = process.argv.includes('--out') ? process.argv[process.argv.indexOf('--out') + 1] : 'results2'
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
const LMS = ['LMS-H10-W2', 'LMS-H10-W4', 'LMS-H10-W8']
const lmsW = (s) => s.split('-')[2]

// ------------------------------------------------------------------ compile & EVM
const srcs = { 'PQAnchor2.sol': { content: fs.readFileSync('PQAnchor2.sol', 'utf8') }, 'LMSVerifier.sol': { content: fs.readFileSync('LMSVerifier.sol', 'utf8') } }
const out = JSON.parse(solc.compile(JSON.stringify({ language: 'Solidity', sources: srcs,
  settings: { optimizer: { enabled: true, runs: 200 }, viaIR: true, evmVersion: 'cancun', outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } } })))
const errs = (out.errors || []).filter(e => e.severity === 'error')
if (errs.length) { console.error(errs.map(e => e.formattedMessage).join('\n')); process.exit(1) }
const C = { anchor: out.contracts['PQAnchor2.sol'].PQAnchor2, lms: out.contracts['LMSVerifier.sol'].LMSVerifier, meter: out.contracts['LMSVerifier.sol'].Meter }
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
    else if (LMS.includes(scheme)) d = { pk: '0x' + (await lmsCall({ ots: lmsW(scheme), pk: true })).pk }
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
    else if (LMS.includes(scheme)) sig = '0x' + (await lmsCall({ ots: lmsW(scheme), msg: m.slice(2) })).sig
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


const M4 = 4, rows = []
for (const s of ['ECDSA', 'ML-DSA-44', 'ML-DSA-65', 'Falcon-512', 'SLH-DSA-128s', 'LMS-H10-W2', 'LMS-H10-W4', 'LMS-H10-W8']) {
  const A = LMS.includes(s) ? lmsA : stubA
  const ds = await register(A, s + '|k1000', s, M4, 'calldata')
  await run(A, s, ds, 1, { leaves: true, keyOnChain: false })
  const r = await run(A, s, ds, 1000, { leaves: true, keyOnChain: false })
  if (!r.ok) { console.log('FAILED', s, r.err || 'invalid'); continue }
  for (const [impl, g] of Object.entries(impls(s))) {
    const p = price(r, s, M4, g)
    rows.push({ variant: 'DR-L (leaves posted, key in calldata)', scheme: s, impl, devices: M4, k: 1000, tx_gas: p.total, per_record: Math.round(p.total / (M4 * 1000)),
      exec: p.exec, zero_bytes: p.z, nonzero_bytes: p.nz, fits_cap: p.total <= CAP })
    console.log(s, impl, Math.round(p.total / (M4 * 1000)), p.total <= CAP)
  }
}
const csv = (rr) => [Object.keys(rr[0]).join(','), ...rr.map(r => Object.values(r).map(v => typeof v === 'string' && v.includes(',') ? `"${v}"` : v).join(','))].join('\n') + '\n'
fs.writeFileSync(`${OUT}/pq2_dr_k1000_m4.csv`, csv(rows))
lmsProc.stdin.end(); process.exit(0)
