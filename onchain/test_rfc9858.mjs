import fs from 'node:fs'; import crypto from 'node:crypto'; import solc from 'solc'; import { Interface } from 'ethers'
import { createVM, runTx } from '@ethereumjs/vm'; import { Common, Hardfork, Mainnet } from '@ethereumjs/common'
import { createFeeMarket1559Tx } from '@ethereumjs/tx'; import { Account, Address, hexToBytes, privateToAddress } from '@ethereumjs/util'
const src = { 'RFCTest.sol': { content: fs.readFileSync('RFCTest.sol', 'utf8') }, 'LMSVerifier3.sol': { content: fs.readFileSync('LMSVerifier3.sol', 'utf8') } }
const out = JSON.parse(solc.compile(JSON.stringify({ language: 'Solidity', sources: src, settings: { optimizer: { enabled: true, runs: 200 }, viaIR: true, evmVersion: 'cancun', outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } } })))
const errs = (out.errors || []).filter(e => e.severity === 'error'); if (errs.length) { console.log(errs.map(e => e.formattedMessage).join('\n')); process.exit(1) }
const C = out.contracts['RFCTest.sol'].RFCTest, iT = new Interface(C.abi)
const common = new Common({ chain: Mainnet, hardfork: Hardfork.Osaka }); const vm = await createVM({ common })
const pk = hexToBytes('0x' + '77'.repeat(32)), s = new Address(privateToAddress(pk)); await vm.stateManager.putAccount(s, new Account(0n, 10n ** 30n))
const tx = createFeeMarket1559Tx({ nonce: 0n, data: hexToBytes('0x' + C.evm.bytecode.object), gasLimit: 16_000_000n, maxFeePerGas: 10n ** 10n }, { common }).sign(pk)
const A = (await runTx(vm, { tx, skipBlockGasLimitValidation: true })).createdAddress
async function verify(pub, sig, msg) {
  const r = await vm.evm.runCall({ to: A, caller: s, data: hexToBytes(iT.encodeFunctionData('verifyHSS', ['0x' + pub, '0x' + sig, '0x' + msg])), gasLimit: 15_000_000n })
  if (r.execResult.exceptionError) return 'revert'
  return iT.decodeFunctionResult('verifyHSS', r.execResult.returnValue)[0]
}
const V = JSON.parse(fs.readFileSync('rfc9858_vectors.json', 'utf8')), res = { rfc: [], fuzz: {} }
for (const [i, c] of V.entries()) {
  const ok = await verify(c.pub, c.sig, c.msg)
  const badMsg = await verify(c.pub, c.sig, c.msg.slice(0, -2) + (c.msg.endsWith('00') ? '01' : '00'))
  const badSig = await verify(c.pub, c.sig.slice(0, 200) + (c.sig[200] === 'f' ? '0' : 'f') + c.sig.slice(201), c.msg)
  res.rfc.push({ test_case: i + 1, valid_accepted: ok, wrong_message: badMsg, tampered_signature: badSig })
}
console.log('RFC 9858 Appendix A (SHA-256/192):', JSON.stringify(res.rfc))
// differential fuzzing: random structural mutations of a valid vector must never verify
const c = V[1]; let accepted = 0, reverted = 0, rejected = 0, N = 600
const mut = [
  (p, g) => [p, g.slice(0, 8) + crypto.randomBytes(4).toString('hex') + g.slice(16)],          // OTS/LMS type code
  (p, g) => [p, g.slice(0, 2 * (crypto.randomInt(g.length / 2)))],                                // truncation
  (p, g) => [p, g + crypto.randomBytes(1 + crypto.randomInt(64)).toString('hex')],                // trailing bytes
  (p, g) => [p, g.slice(0, 8) + 'ffffffff' + g.slice(16)],                                        // q out of range
  (p, g) => [p.slice(0, 6) + '03' + p.slice(8), g],                                               // HSS level mismatch
  (p, g) => { const i = 8 + 2 * crypto.randomInt(g.length / 2 - 4); return [p, g.slice(0, i) + crypto.randomBytes(1).toString('hex') + g.slice(i + 2)] }, // random byte
]
for (let t = 0; t < N; t++) {
  let p, g
  do { [p, g] = mut[t % mut.length](c.pub, c.sig) } while (p === c.pub && g === c.sig)   // skip no-op mutations
  const r = await verify(p, g, c.msg)
  if (r === true) { accepted++; console.log('ACCEPTED mutation kind', t % mut.length, 'changed bytes:', [...Array(Math.max(g.length, c.sig.length) / 2).keys()].filter(i => g.slice(2 * i, 2 * i + 2) !== c.sig.slice(2 * i, 2 * i + 2)).length) }
  else if (r === 'revert') reverted++; else rejected++
}
res.fuzz = { cases: N, accepted, rejected_false: rejected, reverted }
console.log('fuzz:', JSON.stringify(res.fuzz))
fs.mkdirSync('results9', { recursive: true }); fs.writeFileSync('results9/rfc9858.json', JSON.stringify(res, null, 2))
