import fs from 'node:fs'; import crypto from 'node:crypto'; import { spawn } from 'node:child_process'; import readline from 'node:readline'
import solc from 'solc'; import { Interface } from 'ethers'
import { createVM, runTx } from '@ethereumjs/vm'; import { Common, Hardfork, Mainnet } from '@ethereumjs/common'
import { createFeeMarket1559Tx } from '@ethereumjs/tx'; import { Account, Address, hexToBytes, privateToAddress } from '@ethereumjs/util'
const p = spawn('python3', ['lms_signer.py'], { stdio: ['pipe', 'pipe', 'inherit'] }); const rl = readline.createInterface({ input: p.stdout }); const q = []
rl.on('line', l => q.shift()(JSON.parse(l))); const call = (r) => new Promise(res => { q.push(res); p.stdin.write(JSON.stringify(r) + '\n') })
const out = JSON.parse(solc.compile(JSON.stringify({ language: 'Solidity', sources: { 'L.sol': { content: fs.readFileSync('LMSVerifier3.sol', 'utf8') } },
  settings: { optimizer: { enabled: true, runs: 200 }, viaIR: true, evmVersion: 'cancun', outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } } })))
const errs = (out.errors || []).filter(e => e.severity === 'error'); if (errs.length) { console.log(errs.map(e => e.formattedMessage).join('\n')); process.exit(1) }
const common = new Common({ chain: Mainnet, hardfork: Hardfork.Osaka }); const vm = await createVM({ common })
const pk = hexToBytes('0x' + '77'.repeat(32)), s = new Address(privateToAddress(pk)); await vm.stateManager.putAccount(s, new Account(0n, 10n ** 30n))
async function dep(c) { const tx = createFeeMarket1559Tx({ nonce: (await vm.stateManager.getAccount(s)).nonce, data: hexToBytes('0x' + c.evm.bytecode.object), gasLimit: 16_000_000n, maxFeePerGas: 10n ** 10n }, { common }).sign(pk); return (await runTx(vm, { tx, skipBlockGasLimitValidation: true })).createdAddress }
const V = await dep(out.contracts['L.sol'].LMSVerifier3), Mt = await dep(out.contracts['L.sol'].Meter), iM = new Interface(out.contracts['L.sol'].Meter.abi)
async function meter(input) { const r = await vm.evm.runCall({ to: Mt, caller: new Address(hexToBytes('0x' + '11'.repeat(20))), data: hexToBytes(iM.encodeFunctionData('meter', [V.toString(), input])), gasLimit: 15_000_000n }); return iM.decodeFunctionResult('meter', r.execResult.returnValue) }
for (const key of ['H10-W4', 'M24-H10-W4', 'M24-H10-W8', 'HSS-H10W4x2']) {
  const kp = (await call({ key, pk: true })).pk; const gs = []; let ok = true, sl = 0
  for (let t = 0; t < 6; t++) { const m = crypto.randomBytes(32).toString('hex'); const sig = (await call({ key, msg: m })).sig; sl = sig.length / 2
    const [u, k] = await meter('0x' + kp + sig + m); ok = ok && k; gs.push(Number(u)) }
  const m = crypto.randomBytes(32).toString('hex'); const sig = (await call({ key, msg: m })).sig
  const bad = sig.slice(0, 100) + (sig[100] === 'a' ? 'b' : 'a') + sig.slice(101)
  const [, kb] = await meter('0x' + kp + bad + m); const [, km] = await meter('0x' + kp + sig + crypto.randomBytes(32).toString('hex'))
  console.log(key.padEnd(12), 'pk', kp.length / 2, 'sig', sl, 'valid all ok:', ok, '| tampered sig rejected:', !kb, '| wrong msg rejected:', !km, '| gas median', gs.sort((a, b) => a - b)[3], 'range', gs[0], '-', gs[5])
}
p.stdin.end(); process.exit(0)
