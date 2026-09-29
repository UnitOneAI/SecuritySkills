const express = require('express');
const router = express.Router();
const cache = require('./cache');
const db = require('./db');

// Vulnerable: cache key omits tenantId and role, causing cross-tenant and privilege leakage
router.get('/projects/:projectId/summary', async (req, res) => {
  const tenantId = req.session.tenantId;
  const role = req.session.role;
  const projectId = req.params.projectId;

  const cacheKey = `project:${projectId}`;
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
