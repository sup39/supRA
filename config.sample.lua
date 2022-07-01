-- https://www.rfc-editor.org/rfc/rfc4861.html#section-4.2
ra {
  -- hop = 64,
  M = false, -- addresses are available via DHCPv6
  O = false, -- other configuration information is available via DHCPv6
  router_lft = 1800, -- router lifetime(s)
  -- reachable_time = 0,
  -- retrans_timer = 0,
}

-- ra interval(ms)
interval = 600000 -- 10 minutes

-- IPv6 address prefix
prefix '2001:db8:39:efbc::/62' {
  L = true, -- on link
  A = true, -- auto config address
  -- valid_lft = -1, -- valid lifetime(s) (-1=infinity)
  preferred_lft = 3600, -- preferred lifetime(s)
}
prefix '2001:db8:1207::/56' {
  L = true, -- on link
  A = false, -- auto config address
  -- valid_lft = -1, -- valid lifetime(s) (-1=infinity)
  -- preferred_lft = -1, -- preferred lifetime(s) (-1=infinity)
}

-- route
route '2001:db8:426::/55' {
  prf = 'M', -- preference (M/L/H)
  lft = 1800, -- lifetime(s)
}
route '2001:db8:428:abcd::/64' {
  prf = 'H', -- preference (M/L/H)
  lft = 900, -- lifetime(s)
}

-- dns
dns {
  -- lifetime(s)
  lft = 1800, -- 30 minutes
  -- server 1
  '2001:db8:d25::53',
  -- server 2
  '2001:db8:d25::5353',
  -- other servers...
}
