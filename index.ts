import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import path from 'path';
import fs from 'fs';

const app = express();
const PORT = 3000;

app.set('trust proxy', 1);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

const limiter = rateLimit({
  windowMs: 60_000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

app.use(express.static(path.join(process.cwd(), 'public')));

app.use((req: Request, _res: Response, next: NextFunction) => {
  const clientIp =
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    req.headers['x-real-ip'] ||
    req.socket.remoteAddress ||
    'unknown';

  console.log(`[REQ] ${req.method} ${req.path} → ${clientIp}`);
  next();
});

app.get('/', (_req: Request, res: Response) => {
  res.send('OK');
});

app.all('/player/login/dashboard', async (req: Request, res: Response) => {
  let clientData = '';

  if (req.body && Object.keys(req.body).length > 0) {
    clientData = Object.keys(req.body)[0];
  }

  const encodedClientData = Buffer.from(clientData).toString('base64');

  const templatePath = path.join(process.cwd(), 'template', 'dashboard.html');
  const templateContent = fs.readFileSync(templatePath, 'utf-8');

  const htmlContent = templateContent.replace('{{ data }}', encodedClientData);

  res.setHeader('Content-Type', 'text/html');
  res.send(htmlContent);
});

/**
 * 🔥 FIXED LOGIN / REGISTER HANDLER
 */
app.all('/player/growid/login/validate', async (req: Request, res: Response) => {
  try {
    const body = req.body as Record<string, string>;

    const growId = (body.growId || '').trim();
    const password = (body.password || '').trim();
    const email = (body.email || '').trim();
    const tokenInput = body._token || '';
    const isRegister = body.reg === '1' || !!email;

    console.log('[DEBUG BODY]', body);

    // ✅ HARD VALIDATION LOGIN
    if (!isRegister) {
      if (!growId || !password) {
        return res.status(200).json({
          status: 'error',
          message: 'GrowID / Password kosong',
        });
      }
    }

    // ✅ BUILD PAYLOAD SESUAI FORMAT CLIENT
    let rawPayload = '';

    if (isRegister) {
      rawPayload =
        `tankIDName=${growId}` +
        `&tankIDPass=${password}` +
        `&email=${email}` +
        `&_token=${tokenInput}` +
        `&reg=1`;
    } else {
      rawPayload =
        `tankIDName=${growId}` +
        `&tankIDPass=${password}` +
        `&_token=${tokenInput}` +
        `&reg=0`;
    }

    const token = Buffer.from(rawPayload).toString('base64');

    return res.status(200).json({
      status: 'success',
      message: 'Account Validated',
      token,
      url: '',
      accountType: 'growtopia',
    });
  } catch (err) {
    console.log('[ERROR]', err);
    return res.status(500).json({
      status: 'error',
      message: 'Internal Server Error',
    });
  }
});

app.all('/player/growid/checktoken', async (_req: Request, res: Response) => {
  return res.redirect(307, '/player/growid/validate/checktoken');
});

app.all('/player/growid/validate/checktoken', async (req: Request, res: Response) => {
  try {
    const formData = req.body as Record<string, string>;

    let refreshToken = formData.refreshToken;
    let clientData = formData.clientData;

    if (!refreshToken || !clientData) {
      return res.status(200).json({
        status: 'error',
        message: 'Missing token',
      });
    }

    let decoded = Buffer.from(refreshToken, 'base64').toString('utf-8');

    decoded = decoded.replace('&reg=0', '').replace('&reg=1', '');

    const newToken = Buffer.from(
      decoded.replace(
        /(_token=)[^&]*/,
        `$1${Buffer.from(clientData).toString('base64')}`
      )
    ).toString('base64');

    return res.status(200).json({
      status: 'success',
      message: 'OK',
      token: newToken,
      accountType: 'growtopia',
    });
  } catch (err) {
    console.log('[ERROR]', err);
    return res.status(200).json({
      status: 'error',
      message: 'Internal Server Error',
    });
  }
});

app.listen(PORT, () => {
  console.log(`[SERVER] http://localhost:${PORT}`);
});

export default app;
