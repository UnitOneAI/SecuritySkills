const express = require('express');
const router = express.Router();
const cache = require('./cache');
const db = require('./db');

// Benign: tenant-aware scoped caching with proper tenant binding and private response headers
router.get('/projects/:projectId/summary', async (req, res) => {
  const tenantId = req.session.tenantId;
  const role = req.session.role;
  const projectId = req.params.projectId;

  const cacheKey = `tenant:${tenantId}:project:${projectId}:role:${role}`;
  res.set('Cache-Control', 'private, no-store');
  res.set('Vary', 'Authorization, Cookie, X-Tenant-ID');

  const cached = await cache.get(cacheKey);
  if (cached) {
    return res.json(cached);
  }

  const project = await db.findProject(tenantId, projectId);
  if (!project) {
    return res.status(404).json({ error: 'Project not found' });
  }

  const payload = role === 'admin'
    ? { ...project, budget: project.budget, auditLog: project.auditLog }
    : { id: project.id, name: project.name, status: project.status };

  await cache.set(cacheKey, payload, 300);
  return res.json(payload);
});

module.exports = router;
