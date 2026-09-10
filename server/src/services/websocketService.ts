import { WebSocketServer, WebSocket } from 'ws';
import { Server, IncomingMessage } from 'http';
import jwt from 'jsonwebtoken';
import { getJwtSecret } from '../middleware/auth.js';

interface ExtendedWebSocket extends WebSocket {
  subscriptions?: Set<string>;
  isAlive?: boolean;
  user?: any;
}

let wss: WebSocketServer | null = null;

export function extractTokenFromRequest(req: IncomingMessage): string | null {
  try {
    const host = req.headers.host || 'localhost';
    const parsedUrl = new URL(req.url || '', `http://${host}`);
    let token = parsedUrl.searchParams.get('token');
    
    if (!token && req.headers.authorization?.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    }
    
    if (!token && req.headers['sec-websocket-protocol']) {
      const protocols = req.headers['sec-websocket-protocol'].split(',').map(p => p.trim());
      token = protocols.find(p => p.length > 20 && p.includes('.')) || null;
    }
    
    return token;
  } catch {
    return null;
  }
}

export function verifyWebSocketHandshake(req: IncomingMessage): { authenticated: boolean; user?: any; error?: string } {
  const token = extractTokenFromRequest(req);
  if (!token) {
    return { authenticated: false, error: 'Missing authentication token' };
  }

  try {
    const decoded = jwt.verify(token, getJwtSecret());
    return { authenticated: true, user: decoded };
  } catch (err: any) {
    return { authenticated: false, error: 'Invalid or expired token' };
  }
}

export function initWebSocketServer(httpServer: Server) {
  wss = new WebSocketServer({
    server: httpServer,
    path: '/ws/telemetry',
    verifyClient: (info, callback) => {
      const result = verifyWebSocketHandshake(info.req);
      if (!result.authenticated) {
        console.warn(`[WebSocket Security] Rejected unauthenticated connection from ${info.req.socket.remoteAddress}: ${result.error}`);
        callback(false, 401, 'Unauthorized: Valid JWT Bearer token required for live SOC telemetry stream');
      } else {
        callback(true);
      }
    }
  });

  wss.on('connection', (ws: ExtendedWebSocket, req: IncomingMessage) => {
    const auth = verifyWebSocketHandshake(req);
    ws.user = auth.user;
    ws.subscriptions = new Set(['ALL']);
    ws.isAlive = true;
    console.log(`[WebSocket] Telemetry client connected to live SOC stream (User: ${ws.user?.username || 'authenticated'}, Role: ${ws.user?.role || 'Viewer'}).`);

    ws.on('pong', () => {
      ws.isAlive = true;
    });

    // Handshake message
    ws.send(JSON.stringify({
      type: 'HANDSHAKE',
      status: 'CONNECTED',
      channel: 'SOC_LIVE_TELEMETRY',
      availableChannels: ['NETFLOW', 'SIEM', 'DISCOVERY', 'CORRELATION', 'ALL'],
      timestamp: new Date().toISOString()
    }));

    ws.on('message', (data: string) => {
      try {
        const payload = JSON.parse(data.toString());
        if (payload.action === 'SUBSCRIBE' && payload.channel) {
          ws.subscriptions?.add(payload.channel);
          ws.send(JSON.stringify({ type: 'SUBSCRIBED', channel: payload.channel, timestamp: new Date().toISOString() }));
        }
      } catch (e) {
        // Ignore unparseable messages
      }
    });

    ws.on('close', () => {
      console.log('[WebSocket] Telemetry client disconnected.');
    });
  });

  // Regular heartbeat ping (15s) with Ping/Pong keepalive
  const interval = setInterval(() => {
    if (!wss) return;
    const memoryUsageMb = (process.memoryUsage().rss / (1024 * 1024)).toFixed(1);

    wss.clients.forEach((ws: ExtendedWebSocket) => {
      if (ws.isAlive === false) {
        return ws.terminate();
      }
      ws.isAlive = false;
      ws.ping();
    });

    broadcastTelemetryEvent({
      type: 'HEARTBEAT',
      timestamp: new Date().toISOString(),
      activeSensors: 12,
      memoryUsageMb,
      status: 'HEALTHY'
    });
  }, 15000);

  wss.on('close', () => {
    clearInterval(interval);
  });
}

export function broadcastTelemetryEvent(data: any, channel = 'ALL') {
  if (!wss) return;
  const message = JSON.stringify(data);
  wss.clients.forEach((client: ExtendedWebSocket) => {
    if (client.readyState === WebSocket.OPEN) {
      if (!client.subscriptions || client.subscriptions.has('ALL') || client.subscriptions.has(channel)) {
        client.send(message);
      }
    }
  });
}
