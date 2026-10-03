-- Grand Horizon Hotels: referral and daily-check-in ledger
CREATE TABLE IF NOT EXISTS referrals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  referrer_id INTEGER NOT NULL,
  referred_user_id INTEGER NOT NULL UNIQUE,
  rate_percent INTEGER NOT NULL DEFAULT 5,
  first_eligible_deposit_id INTEGER,
  bonus_amount INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','credited')),
  created_at INTEGER NOT NULL,
  credited_at INTEGER,
  FOREIGN KEY (referrer_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (referred_user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (first_eligible_deposit_id) REFERENCES transactions(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS referral_credits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  referral_id INTEGER NOT NULL,
  referrer_id INTEGER NOT NULL,
  deposit_transaction_id INTEGER NOT NULL UNIQUE,
  deposit_amount INTEGER NOT NULL,
  rate_percent INTEGER NOT NULL,
  bonus_amount INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (referral_id) REFERENCES referrals(id) ON DELETE CASCADE,
  FOREIGN KEY (referrer_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (deposit_transaction_id) REFERENCES transactions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS daily_checkins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  checkin_date TEXT NOT NULL,
  bonus_amount INTEGER NOT NULL DEFAULT 400,
  created_at INTEGER NOT NULL,
  UNIQUE(user_id, checkin_date),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_referrals_referrer ON referrals(referrer_id);
CREATE INDEX IF NOT EXISTS idx_referral_credits_referrer ON referral_credits(referrer_id);
CREATE INDEX IF NOT EXISTS idx_daily_checkins_user_date ON daily_checkins(user_id, checkin_date);
