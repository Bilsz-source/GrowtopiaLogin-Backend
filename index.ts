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

  console.log(`[REQ] ${req.method} ${req.path} → ${clientIp} | ${res.statusCode}`);
  next();
});

app.get('/', (_req: Request, res: Response) => {
  res.send('Hello, world!');
});

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

app.all('/player/growid/login/validate', async (req: Request, res: Response) => {
  try {
    const formData = (req.body || {}) as Record<string, any>;

    const _token = String(formData._token || '');
    const growId = String(formData.growId || '');
    const password = String(formData.password || '');
    const email = String(formData.email || '');
    const reg = String(formData.reg || (email ? '1' : '0'));

    let token = '';
    if (email) {
      token = Buffer.from(
        `_token=${_token}&growId=${growId}&password=${password}&email=${email}&reg=${reg === '1' ? '1' : '0'}`,
      ).toString('base64');
    } else {
      token = Buffer.from(
        `_token=${_token}&growId=${growId}&password=${password}&reg=${reg === '1' ? '1' : '0'}`,
      ).toString('base64');
    }

    res.send(
      JSON.stringify({
        status: 'success',
        message: 'Account Validated.',
        token,
        url: '',
        accountType: 'growtopia',
      }),
    );
  } catch (error) {
    console.log(`[ERROR]: ${error}`);
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

    const contentType = String(req.headers['content-type'] || '');

    if (
      contentType.includes('application/json') ||
      (typeof req.body === 'object' &&
        req.body !== null &&
        'refreshToken' in req.body)
    ) {
      const formData = req.body as Record<string, string>;
      refreshToken = formData.refreshToken;
      clientData = formData.clientData;
      console.log(`[CHECKTOKEN] Parsed as JSON/Object`);
    } else if (
      typeof req.body === 'object' &&
      req.body !== null &&
      Object.keys(req.body).length > 0
    ) {
      const formData = req.body as Record<string, string>;
      refreshToken = formData.refreshToken;
      clientData = formData.clientData;
      console.log(`[CHECKTOKEN] Parsed as form-urlencoded`);
    } else if (typeof req.body === 'string' && req.body.length > 0) {
      const params = new URLSearchParams(req.body);
      refreshToken = params.get('refreshToken') || undefined;
      clientData = params.get('clientData') || undefined;
      console.log(`[CHECKTOKEN] Parsed as string/URLSearchParams`);
    }

    if (!refreshToken || !clientData) {
      console.log(`[ERROR]: Missing refreshToken or clientData`);
      res.status(200).json({
        status: 'error',
        message: 'Missing refreshToken or clientData',
      });
      return;
    }

    let decodedRefreshToken = Buffer.from(refreshToken, 'base64').toString('utf-8');

    if (decodedRefreshToken.includes('&reg=0')) {
      decodedRefreshToken = decodedRefreshToken.replace('&reg=0', '');
    } else if (decodedRefreshToken.includes('&reg=1')) {
      decodedRefreshToken = decodedRefreshToken.replace('&reg=1', '');
    }

    const token = Buffer.from(
      decodedRefreshToken.replace(
        /(_token=)[^&]*/,
        `$1${Buffer.from(clientData).toString('base64')}`,
      ),
    ).toString('base64');

    res.send(
      `{"status":"success","message":"Token is valid.","token":"${token}","url":"","accountType":"growtopia"}`,
    );
  } catch (error) {
    console.log(`[ERROR]: ${error}`);
    res.status(200).json({
      status: 'error',
      message: 'Internal Server Error',
    });
  }
});

app.listen(PORT, () => {
  console.log(`[SERVER] Running on http://localhost:${PORT}`);
});

export default app;
