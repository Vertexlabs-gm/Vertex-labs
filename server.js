require('dotenv').config();

const express = require('express');
const cors = require('cors');
const webpush = require('web-push');
const { MongoClient } = require('mongodb');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const MONGODB_DB = process.env.MONGODB_DB || 'devstore';
const VAPID_PUBLIC = process.env.VAPID_PUBLIC;
const VAPID_PRIVATE = process.env.VAPID_PRIVATE;
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || 'mailto:support.vertexlabs@gmail.com';
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'admin@devstore.app').toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

if (!MONGODB_URI) {
  console.error('MONGODB_URI is not configured');
  process.exit(1);
}

if (VAPID_PUBLIC && VAPID_PRIVATE) {
  webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC, VAPID_PRIVATE);
}

const mongo = new MongoClient(MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
let db;

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `scrypt$${salt}$${hash}`;
}

async function verifyPassword(user, password) {
  if (user.passwordHash) {
    const [, salt, expected] = user.passwordHash.split('$');
    if (!salt || !/^[a-f0-9]{128}$/i.test(expected || '')) return false;
    const actual = crypto.scryptSync(password, salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expected, 'hex'));
  }

  if (user.password && user.password === password) {
    await db.collection('users').updateOne(
      { id: user.id },
      { $set: { passwordHash: hashPassword(password) }, $unset: { password: '' } }
    );
    return true;
  }
  return false;
}

async function createSession(userId, role) {
  const token = crypto.randomBytes(32).toString('hex');
  await db.collection('sessions').insertOne({
    tokenHash: crypto.createHash('sha256').update(token).digest('hex'),
    userId,
    role,
    expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
  });
  return token;
}

async function requireSession(req, res, next) {
  const authorization = req.get('authorization') || '';
  const token = authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Sign in required' });

  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const session = await db.collection('sessions').findOne({
    tokenHash,
    expiresAt: { $gt: new Date() }
  });
  if (!session) return res.status(401).json({ error: 'Session expired; sign in again' });
  req.session = session;
  next();
}

function requireAdmin(req, res, next) {
  if (req.session.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    createdAt: user.createdAt,
    subscription: user.subscription || null
  };
}

function secureUrl(value) {
  if (typeof value !== 'string' || value.length > 2048) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password;
  } catch {
    return false;
  }
}

function hasOnlyRemoteMedia(appData) {
  if (appData.icon && !secureUrl(appData.icon)) return false;
  if (appData.apk && !secureUrl(appData.apk)) return false;
  if (appData.screenshots && (
    !Array.isArray(appData.screenshots) ||
    appData.screenshots.some(url => !secureUrl(url))
  )) return false;
  return true;
}

async function migrateLegacyDatabase(database) {
  const dbFile = path.join(__dirname, 'db.json');
  if (!fs.existsSync(dbFile)) return;

  const legacy = JSON.parse(fs.readFileSync(dbFile, 'utf8'));
  if (!legacy || typeof legacy !== 'object') return;

  const apps = legacy.apps || [];
  const users = legacy.users || [];
  const subscriptions = legacy.subscriptions || [];
  const reviewGroups = legacy.reviews || {};

  if (apps.length) {
    await database.collection('apps').bulkWrite(
      apps.map(app => ({
        replaceOne: { filter: { id: app.id }, replacement: app, upsert: true }
      }))
    );
  }
  if (users.length) {
    await database.collection('users').bulkWrite(
      users.map(user => {
        const migratedUser = { ...user };
        if (migratedUser.password && !migratedUser.passwordHash) {
          migratedUser.passwordHash = hashPassword(migratedUser.password);
          delete migratedUser.password;
        }
        return {
          updateOne: {
            filter: { email: user.email },
            update: { $setOnInsert: migratedUser },
            upsert: true
          }
        };
      })
    );
  }
  if (subscriptions.length) {
    await database.collection('subscriptions').bulkWrite(
      subscriptions.map(subscription => ({
        replaceOne: { filter: { endpoint: subscription.endpoint }, replacement: subscription, upsert: true }
      }))
    );
  }

  const reviews = Object.entries(reviewGroups).flatMap(([appId, items]) =>
    (items || []).map(review => ({ ...review, appId }))
  );
  if (reviews.length) {
    await database.collection('reviews').bulkWrite(
      reviews.map(review => ({
        replaceOne: { filter: { id: review.id }, replacement: review, upsert: true }
      }))
    );
  }

  console.log('Migrated legacy db.json data to MongoDB');
}

function start() {
  const offlineApp = express();
  offlineApp.use('/user', express.static(path.join(__dirname, 'APPSTORE USER')));
  offlineApp.use(express.static(__dirname));
  offlineApp.get('/api/health', (req, res) =>
    res.status(503).json({ ok: false, error: 'Database is unavailable' })
  );
  offlineApp.use('/api', (req, res) =>
    res.status(503).json({ error: 'Database is unavailable; try again later' })
  );
  const offlineServer = offlineApp.listen(PORT, () => {
    console.log(`Static app available at http://localhost:${PORT}; waiting for MongoDB`);
  });

  const initialize = async () => {
    try {
      await mongo.connect();
      db = mongo.db(MONGODB_DB);
      await migrateLegacyDatabase(db);

      await db.collection('apps').createIndex({ id: 1 }, { unique: true });
      await db.collection('users').createIndex({ email: 1 }, { unique: true });
      await db.collection('reviews').createIndex({ appId: 1 });
      await db.collection('subscriptions').createIndex({ endpoint: 1 }, { unique: true });
      await db.collection('sessions').createIndex({ tokenHash: 1 }, { unique: true });
      await db.collection('sessions').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
      await db.collection('publishRequests').createIndex({ id: 1 }, { unique: true });
      await db.collection('publishRequests').createIndex({ userId: 1, createdAt: -1 });

      const demoMarker = await db.collection('portalMeta').findOne({ _id: 'demo-publish-requests-v1' });
      if (!demoMarker) {
    const demoNames = [
      'Northstar Tasks', 'Pocket Pantry', 'Orbit Budget', 'Quiet Reader',
      'Trail Finder', 'Bloom Journal', 'Pixel Workshop', 'Focus Garden',
      'Daily Chess', 'Cloud Atlas', 'Sound Desk', 'Study Sprint'
    ];
    const demoStatuses = [
      'pending', 'in_review', 'approved', 'changes_requested',
      'pending', 'rejected', 'in_review', 'pending',
      'approved', 'pending', 'in_review', 'pending'
    ];
    const demoRequests = demoNames.map((name, index) => ({
      id: `demo_request_${index + 1}`,
      userId: `demo_user_${(index % 6) + 1}`,
      publisherName: `Demo Publisher ${(index % 6) + 1}`,
      email: `publisher${(index % 6) + 1}@example.test`,
      name,
      category: ['Productivity', 'Tools', 'Games', 'Education'][index % 4],
      version: `1.${index % 5}.0`,
      size: `${12 + index * 3} MB`,
      description: `Sample app submission ${index + 1} for the publishing review demo.`,
      apkUrl: `https://demo-${index + 1}.supabase.co/storage/v1/object/public/apps/${index + 1}.apk`,
      iconUrl: `https://demo-${index + 1}.supabase.co/storage/v1/object/public/apps/${index + 1}-icon.png`,
      screenshotUrls: [1, 2, 3, 4].map(number =>
        `https://demo-${index + 1}.supabase.co/storage/v1/object/public/apps/${index + 1}-screen-${number}.jpg`
      ),
      status: demoStatuses[index],
      createdAt: new Date(Date.now() - (index + 1) * 3 * 60 * 60 * 1000).toISOString(),
      isDemo: true
    }));
    await db.collection('publishRequests').bulkWrite(demoRequests.map(request => ({
      replaceOne: { filter: { id: request.id }, replacement: request, upsert: true }
    })));
    await db.collection('portalMeta').insertOne({ _id: 'demo-publish-requests-v1', createdAt: new Date() });
    console.log('Seeded 12 clearly labeled demo publish requests');
      }

  const app = express();
  app.use(cors({ origin: '*' }));
  app.use(express.json({ limit: '20mb' }));
  app.use('/user', express.static(path.join(__dirname, 'APPSTORE USER')));
  app.use(express.static(__dirname));

  app.post('/api/auth/login', async (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    if (email === ADMIN_EMAIL && password === ADMIN_PASSWORD) {
      const token = await createSession(null, 'admin');
      return res.json({ success: true, role: 'admin', name: 'Developer', token });
    }

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    let user = await db.collection('users').findOne({ email });
    if (!user) {
      user = {
        id: `u_${crypto.randomUUID()}`,
        email,
        name: email.split('@')[0],
        passwordHash: hashPassword(password),
        createdAt: new Date().toISOString(),
        premium: false
      };
      await db.collection('users').insertOne(user);
    } else if (!(await verifyPassword(user, password))) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    const token = await createSession(user.id, 'user');
    res.json({ success: true, role: 'user', name: user.name, premium: user.premium, token });
  });

  app.post('/api/portal/auth/signup', async (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase();
    const name = String(req.body.name || '').trim().slice(0, 60) || email.split('@')[0];
    const password = String(req.body.password || '');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 8) {
      return res.status(400).json({ error: 'Enter a valid email and a password of at least 8 characters' });
    }

    const users = db.collection('users');
    if (await users.findOne({ email })) return res.status(409).json({ error: 'An account with that email already exists' });
    const user = {
      id: `u_${crypto.randomUUID()}`,
      email,
      name,
      passwordHash: hashPassword(password),
      createdAt: new Date().toISOString(),
      subscription: null
    };
    try {
      await users.insertOne(user);
    } catch (error) {
      if (error.code === 11000) return res.status(409).json({ error: 'An account with that email already exists' });
      throw error;
    }
    const token = await createSession(user.id, 'user');
    res.status(201).json({ success: true, token, user: publicUser(user) });
  });

  app.post('/api/portal/auth/login', async (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const user = await db.collection('users').findOne({ email });
    if (!user || !(await verifyPassword(user, password))) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    const token = await createSession(user.id, 'user');
    res.json({ success: true, token, user: publicUser(user) });
  });

  app.get('/api/portal/me', requireSession, async (req, res) => {
    if (req.session.role === 'admin') return res.json({ role: 'admin' });
    const user = await db.collection('users').findOne({ id: req.session.userId });
    if (!user) return res.status(404).json({ error: 'Account not found' });
    res.json({ role: 'user', user: publicUser(user) });
  });

  app.post('/api/portal/subscription/demo', requireSession, async (req, res) => {
    if (req.session.role !== 'user') return res.status(403).json({ error: 'User account required' });
    const users = db.collection('users');
    const user = await users.findOne({ id: req.session.userId });
    if (!user) return res.status(404).json({ error: 'Account not found' });
    if (user.subscription && Date.parse(user.subscription.expiresAt) > Date.now()) {
      return res.json({ success: true, subscription: user.subscription });
    }
    if (user.demoSubscriptionUsedAt) {
      return res.status(409).json({ error: 'The demo subscription has already been used for this account' });
    }
    const subscription = {
      status: 'active',
      mode: 'demo',
      plan: 'Demo Publisher',
      startedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
    };
    await users.updateOne(
      { id: user.id },
      { $set: { subscription, demoSubscriptionUsedAt: subscription.startedAt } }
    );
    res.json({ success: true, subscription });
  });

  app.get('/api/portal/requests', requireSession, async (req, res) => {
    if (req.session.role !== 'user') return res.status(403).json({ error: 'User account required' });
    const requests = await db.collection('publishRequests')
      .find({ userId: req.session.userId, isDemo: { $ne: true } }, { projection: { _id: 0 } })
      .sort({ createdAt: -1 })
      .limit(100)
      .toArray();
    res.json(requests);
  });

  app.post('/api/portal/requests', requireSession, async (req, res) => {
    if (req.session.role !== 'user') return res.status(403).json({ error: 'User account required' });
    const user = await db.collection('users').findOne({ id: req.session.userId });
    if (!user) return res.status(404).json({ error: 'Account not found' });
    if (
      !user.subscription ||
      user.subscription.status !== 'active' ||
      Date.parse(user.subscription.expiresAt) <= Date.now()
    ) return res.status(402).json({ error: 'Activate a subscription before submitting an app' });

    const { name, category, version, size, description, apkUrl, iconUrl, screenshotUrls } = req.body;
    const screenshots = Array.isArray(screenshotUrls) ? screenshotUrls : [];
    if (
      typeof name !== 'string' || !name.trim() || name.length > 80 ||
      typeof category !== 'string' || !category.trim() || category.length > 40 ||
      typeof version !== 'string' || !version.trim() || version.length > 30 ||
      typeof size !== 'string' || size.length > 30 ||
      typeof description !== 'string' || !description.trim() || description.length > 2000 ||
      !secureUrl(apkUrl) || !secureUrl(iconUrl) ||
      screenshots.length !== 4 || screenshots.some(url => !secureUrl(url))
    ) return res.status(400).json({ error: 'Complete all fields and provide HTTPS file URLs (1 icon and 4 screenshots)' });

    const publishRequest = {
      id: `request_${crypto.randomUUID()}`,
      userId: user.id,
      publisherName: user.name,
      email: user.email,
      name: name.trim(),
      category: category.trim(),
      version: version.trim(),
      size: size.trim() || '—',
      description: description.trim(),
      apkUrl,
      iconUrl,
      screenshotUrls: screenshots,
      status: 'pending',
      createdAt: new Date().toISOString(),
      isDemo: false
    };
    await db.collection('publishRequests').insertOne(publishRequest);
    res.status(201).json({ success: true, request: publishRequest });
  });

  app.get('/api/portal/admin/data', requireSession, requireAdmin, async (req, res) => {
    const [users, requests, reviews] = await Promise.all([
      db.collection('users')
        .find({}, { projection: { _id: 0, password: 0, passwordHash: 0, demoSubscriptionUsedAt: 0 } })
        .sort({ createdAt: -1 })
        .limit(200)
        .toArray(),
      db.collection('publishRequests')
        .find({}, { projection: { _id: 0 } })
        .sort({ createdAt: -1 })
        .limit(200)
        .toArray(),
      db.collection('reviews')
        .find({}, { projection: { _id: 0 } })
        .sort({ time: -1 })
        .limit(200)
        .toArray()
    ]);
    res.json({ users, requests, reviews });
  });

  app.patch('/api/portal/admin/requests/:requestId', requireSession, requireAdmin, async (req, res) => {
    const { status } = req.body;
    if (!['in_review', 'approved', 'rejected', 'changes_requested'].includes(status)) {
      return res.status(400).json({ error: 'Invalid review status' });
    }
    const requests = db.collection('publishRequests');
    const publishRequest = await requests.findOne({ id: req.params.requestId });
    if (!publishRequest) return res.status(404).json({ error: 'Publish request not found' });

    await requests.updateOne(
      { id: publishRequest.id },
      { $set: { status, reviewedAt: new Date().toISOString() } }
    );
    if (status === 'approved' && !publishRequest.isDemo) {
      await db.collection('apps').replaceOne(
        { id: `submitted_${publishRequest.id}` },
        {
          id: `submitted_${publishRequest.id}`,
          name: publishRequest.name,
          dev: publishRequest.publisherName,
          category: publishRequest.category,
          desc: publishRequest.description,
          version: publishRequest.version,
          size: publishRequest.size,
          color: '#1a73e8',
          rating: 0,
          downloads: '0+',
          updated: new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
          recommended: false,
          icon: publishRequest.iconUrl,
          screenshots: publishRequest.screenshotUrls,
          apk: publishRequest.apkUrl
        },
        { upsert: true }
      );
    }
    res.json({ success: true, id: publishRequest.id, status });
  });

  app.get('/api/apps', async (req, res) => {
    const apps = await db.collection('apps').find({}, { projection: { _id: 0 } }).toArray();
    res.json(apps);
  });

  app.post('/api/apps', requireSession, requireAdmin, async (req, res) => {
    const appData = req.body;
    if (!appData || !appData.id) return res.status(400).json({ error: 'Invalid app data' });
    if (!hasOnlyRemoteMedia(appData)) {
      return res.status(400).json({ error: 'App media must be stored as HTTPS URLs, not embedded files' });
    }

    await db.collection('apps').replaceOne({ id: appData.id }, appData, { upsert: true });
    await broadcastPush('New App Published', `${appData.name} is now available!`);
    res.json({ success: true, app: appData });
  });

  app.put('/api/apps/:appId', requireSession, requireAdmin, async (req, res) => {
    const appData = req.body;
    if (!hasOnlyRemoteMedia(appData)) {
      return res.status(400).json({ error: 'App media must be stored as HTTPS URLs, not embedded files' });
    }
    const result = await db.collection('apps').findOneAndUpdate(
      { id: req.params.appId },
      { $set: { ...appData, id: req.params.appId } },
      { returnDocument: 'after', projection: { _id: 0 } }
    );
    if (!result) return res.status(404).json({ error: 'App not found' });
    res.json({ success: true, app: result });
  });

  app.delete('/api/apps/:appId', requireSession, requireAdmin, async (req, res) => {
    await db.collection('apps').deleteOne({ id: req.params.appId });
    res.json({ success: true });
  });

  app.get('/api/reviews/:appId', async (req, res) => {
    const reviews = await db.collection('reviews')
      .find({ appId: req.params.appId }, { projection: { _id: 0 } })
      .sort({ time: -1 })
      .toArray();
    res.json(reviews);
  });

  app.post('/api/reviews/:appId', async (req, res) => {
    const { appId } = req.params;
    const { author, text, rating } = req.body;
    if (typeof text !== 'string' || !text.trim() || text.length > 2000) {
      return res.status(400).json({ error: 'Review text is required and must be 2000 characters or fewer' });
    }
    const score = Number(rating || 5);
    if (!Number.isInteger(score) || score < 1 || score > 5) {
      return res.status(400).json({ error: 'Rating must be between 1 and 5' });
    }

    const review = {
      id: `r_${crypto.randomUUID()}`,
      appId,
      author: typeof author === 'string' && author.trim() ? author.trim().slice(0, 80) : 'Anonymous',
      text: text.trim(),
      rating: score,
      time: Date.now()
    };
    await db.collection('reviews').insertOne(review);
    res.json({ success: true, review });
  });

  app.get('/api/push/key', (req, res) => res.json({ publicKey: VAPID_PUBLIC }));

  app.post('/api/push/subscribe', async (req, res) => {
    const sub = req.body;
    if (!sub || !sub.endpoint) return res.status(400).json({ error: 'Invalid subscription' });
    await db.collection('subscriptions').replaceOne(
      { endpoint: sub.endpoint },
      sub,
      { upsert: true }
    );
    res.json({ success: true });
  });

  app.post('/api/push/broadcast', requireSession, requireAdmin, async (req, res) => {
    const { title = 'DevStore', body = 'There is a new update.' } = req.body;
    await broadcastPush(title, body);
    res.json({ success: true });
  });

  async function broadcastPush(title, body) {
    const payload = JSON.stringify({ title, body });
    const subscriptions = await db.collection('subscriptions').find({}, { projection: { _id: 0 } }).toArray();
    if (!subscriptions.length) return;
    await Promise.allSettled(subscriptions.map(subscription =>
      webpush.sendNotification(subscription, payload)
    ));
  }

  app.get('/api/health', async (req, res) => {
    try {
      await db.command({ ping: 1 });
      res.json({ ok: true, time: Date.now(), database: MONGODB_DB });
    } catch (error) {
      res.status(503).json({ ok: false, error: 'Database is unavailable' });
    }
  });

  offlineServer.close(() => {
    app.listen(PORT, () => {
      console.log(`DevStore Backend running on http://localhost:${PORT}`);
      console.log(`MongoDB database: ${MONGODB_DB}`);
      console.log(`User publishing portal: http://localhost:${PORT}/user/`);
    });
  });
    } catch (error) {
      console.error(`MongoDB is unavailable: ${error.message}. Retrying in 10 seconds.`);
      const retryTimer = setTimeout(initialize, 10000);
      retryTimer.unref();
    }
  };

  initialize();
}

start();
