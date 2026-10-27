import test from 'node:test';
import assert from 'node:assert/strict';
import { googleAuth, signup, signin } from '../controllers/auth.js';
import { addVideo, updateVideo, search } from '../controllers/video.js';
import { getUser, update } from '../controllers/user.js';
import User from '../models/User.js';
import Video from '../models/Video.js';

const response = () => ({ status() { return this; }, json(data) { this.data = data; return this; }, send() { return this; } });

test('email-only Google account takeover is rejected before account lookup', async () => {
  let err;
  await googleAuth({body:{email:'victim@example.com'}}, response(), e => err=e);
  assert.equal(err.status,401);
});
test('invalid Firebase token cannot create a session', async () => {
  process.env.FIREBASE_PROJECT_ID='test-project';
  let err;
  await googleAuth({body:{idToken:'forged-token'}}, response(), e => err=e);
  assert.equal(err.status,401);
});
test('Mongo query operators cannot be submitted as sign-in credentials', async () => {
  let err;
  await signin({body:{name:{$ne:null},password:'password'}}, response(), e => err=e);
  assert.equal(err.status,401);
});
test('signup ignores caller account flags and hashes the password', async (t) => {
  let created;
  t.mock.method(User.prototype,'save',async function(){created=this;return this;});
  await signup({body:{name:'alice',email:'alice@example.com',password:'long-secret',fromGoogle:true,subscribers:999}},response(),e=>{throw e;});
  assert.equal(created.fromGoogle,false);
  assert.equal(created.subscribers,0);
  assert.notEqual(created.password,'long-secret');
});
test('creating videos cannot impersonate another owner or forge engagement', async (t) => {
  t.mock.method(Video.prototype,'save',async function(){return this;});
  const res=response();
  await addVideo({user:{id:'owner'},body:{userId:'victim',title:'test',views:999,likes:['fake']}},res,e=>{throw e;});
  assert.equal(res.data.userId,'owner');
  assert.equal(res.data.views,0);
  assert.equal(res.data.likes.length,0);
});
test('updating video metadata cannot transfer ownership', async (t) => {
  t.mock.method(Video,'findById',async()=>({userId:'owner'}));
  let update;
  t.mock.method(Video,'findByIdAndUpdate',async(id,change)=>{update=change;return {};});
  await updateVideo({user:{id:'owner'},params:{id:'video'},body:{userId:'victim',views:999,title:'new title'}},response(),e=>{throw e;});
  assert.deepEqual(update.$set,{title:'new title'});
});
test('public profiles never return credential or private identity fields', async (t) => {
  t.mock.method(User,'findById',async()=>({toObject:()=>({name:'alice',password:'hash',email:'private@example.com',firebaseUid:'uid'})}));
  const res=response();
  await getUser({params:{id:'alice'}},res,e=>{throw e;});
  assert.deepEqual(res.data,{name:'alice'});
});
test('profile updates cannot inject a plaintext password or account flags', async (t) => {
  let change;
  t.mock.method(User,'findByIdAndUpdate',async(id,data)=>{change=data;return {toObject:()=>({name:'new',password:'hash'})};});
  const res=response();
  await update({params:{id:'owner'},user:{id:'owner'},body:{name:'new',password:'plaintext',fromGoogle:true}},res,e=>{throw e;});
  assert.deepEqual(change.$set,{name:'new'});
  assert.deepEqual(res.data,{name:'new'});
});
test('search treats regular expression syntax as literal text', async (t) => {
  let query;
  t.mock.method(Video,'find',q=>{query=q;return {limit:async()=>[]};});
  await search({query:{q:'(a+)+$'}},response(),e=>{throw e;});
  assert.equal(new RegExp(query.title.$regex).test('(a+)+$'),true);
  assert.equal(new RegExp(query.title.$regex).test('aaaa'),false);
});
