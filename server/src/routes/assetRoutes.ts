import { Request, Response, Router } from 'express';
import { memoryDb, pushBounded } from '../db/client.js';
import { requireRole } from '../middleware/auth.js';

export const assetRouter = Router();

assetRouter.get('/', requireRole(['Admin', 'Analyst', 'Viewer']), (req: Request, res: Response) => {
  return res.json({
    count: memoryDb.assets.length,
    assets: memoryDb.assets
  });
});

assetRouter.post('/', requireRole(['Admin', 'Analyst']), (req: Request, res: Response) => {
  const { hostname, ip_address, mac_address, os_name, owner, tags } = req.body;

  if (!hostname || !ip_address) {
    return res.status(400).json({ error: 'Hostname and IP address are required' });
  }

  const newAsset = {
    id: memoryDb.assets.length + 1,
    hostname,
    ip_address,
    mac_address: mac_address || '00:00:00:00:00:00',
    os_name: os_name || 'Generic Linux / Windows',
    status: 'Active',
    installed_software: [],
    running_services: [],
    owner: owner || 'SOC Inventory',
    tags: tags || ['Discovered']
  };

  pushBounded(memoryDb.assets, newAsset, 1000);
  return res.status(201).json({ message: 'Asset registered successfully', asset: newAsset });
});
