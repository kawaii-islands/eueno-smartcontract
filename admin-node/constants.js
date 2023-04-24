const sector_sizes = {
  "sector-size2-kib": 1<<11,
  "sector-size4-kib": 1<<12,
  "sector-size16-kib": 1<<14,
  "sector-size32-kib": 1<<15,
  "sector-size8-mib": 1<<23,
  "sector-size16-mib": 1<<24,
  "sector-size512-mib": 1<<29,
  "sector-size1-gib": 1<<30,
  "sector-size32-gib": 1<<35,
  "sector-size64-gib": 1<<36,
};

const api_versions = {
  "1.0.0": "V1_0_0",
  "1.1.0": "V1_1_0",
};

module.exports = { api_versions, sector_sizes };
