CREATE TABLE IF NOT EXISTS members (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  membership_tier TEXT NOT NULL DEFAULT 'standard',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS bookings (
  id TEXT PRIMARY KEY,
  member_id TEXT NOT NULL,
  property_name TEXT NOT NULL,
  room_type TEXT NOT NULL,
  check_in TEXT NOT NULL,
  check_out TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'confirmed',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (member_id) REFERENCES members(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_bookings_member_id ON bookings(member_id);
CREATE INDEX IF NOT EXISTS idx_bookings_check_in ON bookings(check_in);

CREATE TABLE IF NOT EXISTS assets (
  key TEXT PRIMARY KEY,
  member_id TEXT,
  content_type TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (member_id) REFERENCES members(id) ON DELETE SET NULL
);
