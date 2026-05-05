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
  validate: { trustProxy: false, xForwardedForHeader: false },
});
app.use(limiter);

app.use(express.static(path.join(process.cwd(), 'public')));

// logging
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
  res.send('Hello, world!');
});

/**
 * DASHBOARD
 */
app.all('/player/login/dashboard', async (req: Request, res: Response) => {
  const body = req.body;
  let clientData = '';

  if (body && typeof body === 'object' && Object.keys(body).length > 0) {
    clientData = Object.keys(body)[0];
  }

  const encodedClientData = Buffer.from(clientData).toString('base64');

  const templatePath = path.join(process.cwd(), 'template', 'dashboard.html');
  const templateContent = fs.readFileSync(templatePath, 'utf-8');

  const htmlContent = templateContent.replace('{{ data }}', encodedClientData);

  res.setHeader('Content-Type', 'text/html');
  res.send(htmlContent);
});

/**
 * VALIDATE LOGIN / REGISTER
 */
app.all('/player/growid/login/validate', async (req: Request, res: Response) => {
  try {
    const formData = req.body as Record<string, string>;

    const _token = formData._token || '';
    const growId = (formData.growId || '').trim();
    const password = (formData.password || '').trim();
    const email = (formData.email || '').trim();
    const isRegister = formData.reg === '1' || !!email;

    console.log('[DEBUG]', { growId, password, email, isRegister });

    let rawPayload = '';

    /**
     * ✅ REGISTER MODE (boleh kosong)
     */
    if (isRegister) {
      rawPayload =
        `tankIDName=${growId || ''}` +
        `&tankIDPass=${password || ''}` +
        `&email=${email || ''}` +
        `&reg=1`;
    } else {
      /**
       * ✅ LOGIN MODE (WAJIB VALID)
       */
      if (!growId || !password) {
        return res.status(200).json({
          status: 'error',
          message: 'Invalid credentials',
        });
      }

      // sanitize basic
      const safeGrowId = growId.replace(/[^A-Za-z0-9]/g, '');
      const safePassword = password.replace(/[^A-Za-z0-9@._!\-]/g, '');

      rawPayload =
        `tankIDName=${safeGrowId}` +
        `&tankIDPass=${safePassword}` +
        `&reg=0`;
    }

    const token = Buffer.from(rawPayload).toString('base64');

    return res.json({
      status: 'success',
      message: 'Account Validated.',
      token,
      url: '',
      accountType: 'growtopia',
    });
  } catch (error) {
    console.log('[ERROR]', error);
    return res.status(500).json({
      status: 'error',
      message: 'Internal Server Error',
    });
  }
});

/**
 * CHECKTOKEN REDIRECT
 */
app.all('/player/growid/checktoken', async (_req: Request, res: Response) => {
  return res.redirect(307, '/player/growid/validate/checktoken');
});

/**
 * VALIDATE CHECKTOKEN
 */
app.all('/player/growid/validate/checktoken', async (req: Request, res: Response) => {
  try {
    let refreshToken: string | undefined;
    let clientData: string | undefined;

    const formData = req.body as Record<string, string>;

    if ('refreshToken' in formData || 'clientData' in formData) {
      refreshToken = formData.refreshToken;
      clientData = formData.clientData;
    } else if (Object.keys(formData).length === 1) {
      const rawPayload = Object.keys(formData)[0];
      const params = new URLSearchParams(rawPayload);
      refreshToken = params.get('refreshToken') || undefined;
      clientData = params.get('clientData') || undefined;
    }

    if (!refreshToken || !clientData) {
      return res.json({
        status: 'error',
        message: 'Missing refreshToken or clientData',
      });
    }

    let decoded = Buffer.from(refreshToken, 'base64').toString('utf-8');

    decoded = decoded.replace('&reg=0', '').replace('&reg=1', '');

    const token = Buffer.from(
      decoded.replace(
        /(_token=)[^&]*/,
        `$1${Buffer.from(clientData).toString('base64')}`,
      ),
    ).toString('base64');

    return res.json({
      status: 'success',
      message: 'Account Validated.',
      token,
      url: '',
      accountType: 'growtopia',
      accountAge: 2,
    });
  } catch (error) {
    console.log('[ERROR]', error);
    return res.json({
      status: 'error',
      message: 'Internal Server Error',
    });
  }
});

app.listen(PORT, () => {
  console.log(`[SERVER] Running on http://localhost:${PORT}`);
});

export default app;
