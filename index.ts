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

app.use((req: Request, res: Response, next: NextFunction) => {
  const clientIp =
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    (req.headers['x-real-ip'] as string) ||
    req.socket.remoteAddress ||
    'unknown';

  console.log(`[REQ] ${req.method} ${req.path} → ${clientIp}`);
  next();
});

app.get('/', (_req: Request, res: Response) => {
  res.send('Hello, world!');
});

app.all('/player/login/dashboard', async (req: Request, res: Response) => {
  try {
    const body = req.body;
    let clientData = '';

    if (body && typeof body === 'object' && Object.keys(body).length > 0) {
      const firstKey = Object.keys(body)[0];
      clientData = body[firstKey] || '';
    }

    const encodedClientData = Buffer.from(clientData).toString('base64');

    const templatePath = path.join(process.cwd(), 'template', 'dashboard.html');
    let templateContent = fs.readFileSync(templatePath, 'utf-8');
    const htmlContent = templateContent.replace('{{ data }}', encodedClientData);

    res.setHeader('Content-Type', 'text/html');
    res.send(htmlContent);
  } catch (error) {
    console.log(`[ERROR /dashboard]: ${error}`);
    res.status(500).send('Internal Server Error');
  }
});

app.all('/player/growid/login/validate', async (req: Request, res: Response) => {
  try {
    const formData = req.body || {};

    const _token = String(formData._token || '').trim();
    const growId = String(formData.growId || '').trim();
    const password = String(formData.password || '').trim();
    const email = String(formData.email || '').trim();
    const reg = String(formData.reg || (email ? '1' : '0')).trim();

    console.log(`[VALIDATE] growId=${growId}, password length=${password.length}, email=${email}, reg=${reg}`);

    let rawTokenString = '';
    if (email) {
      rawTokenString = `_token=${_token}&growId=${growId}&password=${password}&email=${email}&reg=${reg === '1' ? '1' : '0'}`;
    } else {
      rawTokenString = `_token=${_token}&growId=${growId}&password=${password}&reg=${reg === '1' ? '1' : '0'}`;
    }

    const token = Buffer.from(rawTokenString).toString('base64');

    res.json({
      status: 'success',
      message: 'Account Validated.',
      token: token,
      url: '',
      accountType: 'growtopia',
    });
  } catch (error) {
    console.log(`[ERROR /validate]: ${error}`);
    res.status(500).json({
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
    let refreshToken: string | undefined;
    let clientData: string | undefined;

    if (req.body && typeof req.body === 'object') {
      refreshToken = req.body.refreshToken;
      clientData = req.body.clientData;
    }

    if (!refreshToken || !clientData) {
      console.log(`[ERROR /checktoken] Missing refreshToken or clientData`);
      res.status(200).json({
        status: 'error',
        message: 'Missing refreshToken or clientData',
      });
      return;
    }

    let decodedRefreshToken = Buffer.from(refreshToken, 'base64').toString('utf-8');
    decodedRefreshToken = decodedRefreshToken.replace(/&reg=[01]/, '');

    const newToken = Buffer.from(
      decodedRefreshToken.replace(
        /(_token=)[^&]*/,
        `$1${Buffer.from(clientData).toString('base64')}`
      )
    ).toString('base64');

    res.json({
      status: 'success',
      message: 'Token is valid.',
      token: newToken,
      url: '',
      accountType: 'growtopia',
    });
  } catch (error) {
    console.log(`[ERROR /checktoken]: ${error}`);
    res.status(200).json({
      status: 'error',
      message: 'Internal Server Error',
    });
  }
});

app.all('/player/validate/close', async (_req: Request, res: Response) => {
  res.send('<script>window.close();</script>');
});

app.listen(PORT, () => {
  console.log(`[SERVER] Running on http://localhost:${PORT}`);
});

export default app;
