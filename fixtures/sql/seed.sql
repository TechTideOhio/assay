INSERT INTO tasks (id, title, status, created_at) VALUES
('t-01', 'Build Tool 1 reval', 'done', '2026-10-30T08:00:00Z'),
('t-02', 'Build Tool 2 gild', 'done', '2026-10-30T10:00:00Z'),
('t-03', 'Build Tool 3 tessel', 'done', '2026-10-30T12:00:00Z'),
('t-04', 'Build Tool 4 assay', 'in_progress', '2026-10-31T09:00:00Z');

INSERT INTO runs (id, task_id, agent_id, exit_code) VALUES
('run-01', 't-01', 'antigravity', 0),
('run-02', 't-02', 'opencode', 0),
('run-03', 't-03', 'antigravity', 0);
