import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import { RpcClient, validateReview, reviewFinding } from './rpc.mjs';

const review = { severity: 'HIGH', explanation: 'Entrada externa alcança SQL.', remediation: 'Parametrize.', corrected_code: 'cursor.execute(query, params)', possible_false_positive: false };
function childMock(handler) {
  const child = new EventEmitter(); child.stdout = new PassThrough(); child.stderr = new PassThrough();
  child.stdin = new Writable({ write(chunk, encoding, callback) { handler(JSON.parse(chunk.toString()), message => child.stdout.write(JSON.stringify(message) + '\n')); callback(); } });
  return child;
}

test('initialize precedes initialized notification', async () => {
  const seen = []; const rpc = new RpcClient(childMock((m, send) => { seen.push(m.method); if (m.id) send({id:m.id,result:{}}); }));
  await rpc.initialize(); assert.deepEqual(seen,['initialize','initialized']);
});
test('correlates out-of-order responses', async () => {
  const pending = []; const rpc = new RpcClient(childMock((m,send) => { pending.push([m,send]); if(pending.length===2) for(const [item,reply] of pending.reverse()) reply({id:item.id,result:item.method}); }));
  assert.deepEqual(await Promise.all([rpc.call('first'),rpc.call('second')]),['first','second']);
});
test('rejects pending requests on disconnection', async () => {
  const child = childMock(() => {}), rpc = new RpcClient(child); const pending = rpc.call('account/read'); child.emit('exit',1); await assert.rejects(pending,/disconnected/);
});
test('never approves server tool requests', async () => {
  let response; const child = childMock(m => { response = m; }); new RpcClient(child);
  child.stdout.write(JSON.stringify({id:99,method:'item/commandExecution/requestApproval'})+'\n');
  assert.equal(response.error.code,-32601);
});
test('request timeout releases pending map', async () => {
  const rpc = new RpcClient(childMock(() => {}),5); await assert.rejects(rpc.call('test'),/timeout/); assert.equal(rpc.pending.size,0);
});
test('rejects invalid severity and malformed content', () => {
  assert.throws(()=>validateReview({...review,severity:'SAFE'})); assert.throws(()=>validateReview({...review,corrected_code:42})); assert.deepEqual(validateReview(review),review);
});
test('collects completed review and cleans listeners', async () => {
  const rpc = new RpcClient(childMock((m,send) => {
    if(m.method==='thread/start') { assert.equal(m.params.sandbox,'read-only'); send({id:m.id,result:{thread:{id:'thread1'}}}); }
    if(m.method==='turn/start') {
      send({id:m.id,result:{turn:{id:'turn1'}}});
      send({method:'item/completed',params:{threadId:'thread1',item:{type:'agentMessage',text:JSON.stringify(review)}}});
      send({method:'turn/completed',params:{threadId:'thread1',turn:{id:'turn1',status:'completed'}}});
    }
  }));
  const result = await reviewFinding(rpc,{rule:'S004'},'/tmp',200);
  assert.equal(result.provider,'codex'); assert.equal(result.severity,'HIGH'); assert.equal(rpc.listenerCount('notification'),0);
});
test('failed review interrupts and does not invent result', async () => {
  let interrupted = false;
  const rpc = new RpcClient(childMock((m,send) => {
    if(m.method==='thread/start') send({id:m.id,result:{thread:{id:'t'}}});
    if(m.method==='turn/start') { send({id:m.id,result:{turn:{id:'u'}}}); send({method:'turn/completed',params:{threadId:'t',turn:{status:'failed'}}}); }
    if(m.method==='turn/interrupt') { interrupted=true; send({id:m.id,result:{}}); }
  }));
  await assert.rejects(reviewFinding(rpc,{rule:'S004'},'/tmp',200)); assert.equal(interrupted,true);
});
