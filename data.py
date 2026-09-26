"""
data.py — the real Blue Depth registry vs. the decoy registry.
The decoy set is written to be just as plausible as the real one —
no "FAKE"/"SYNTHETIC" markers — so a side-by-side comparison in the
dashboard, not a label, is what reveals the swap.
"""

REAL_SPECIES = [
    "Riftia pachyptila (giant tube worm)",
    "Alvinella pompejana (Pompeii worm)",
    "Bathymodiolus thermophilus (vent mussel)",
    "Chorocaris chacei (vent shrimp)",
    "Kiwa hirsuta (yeti crab)",
]
REAL_EXPEDITIONS = [
    {"name": "Nautilus-14", "year": 2026, "region": "Mariana margin"},
    {"name": "Trident-9", "year": 2025, "region": "Juan de Fuca ridge"},
]
REAL_SAMPLES = [
    {"id": "BD-3391", "species": "Riftia pachyptila", "depth_m": 2540, "site": "Nautilus-14 / Vent A3", "status": "Catalogued"},
    {"id": "BD-3392", "species": "Alvinella pompejana", "depth_m": 2510, "site": "Nautilus-14 / Vent A3", "status": "Catalogued"},
    {"id": "BD-3407", "species": "Bathymodiolus thermophilus", "depth_m": 2488, "site": "Nautilus-14 / Vent B1", "status": "Under review"},
    {"id": "BD-3412", "species": "Chorocaris chacei", "depth_m": 2601, "site": "Nautilus-14 / Vent B2", "status": "Catalogued"},
    {"id": "BD-3419", "species": "Kiwa hirsuta", "depth_m": 2733, "site": "Nautilus-14 / Vent C1", "status": "Sequencing pending"},
]
REAL_USERS = [
    {"id": "u-114", "name": "A. Renard", "role": "Lead Marine Biologist"},
    {"id": "u-118", "name": "M. Okafor", "role": "Genomics"},
]
REAL_CONFIG = {"db_host": "prod-ocean-db.bluedepth.org", "backup_region": "us-west2", "encryption": "AES-256-GCM"}

# ---------------- decoy registry: same shape, different real-looking content ----------------

DECOY_SPECIES = [
    "Calyptogena magnifica",
    "Osedax mucofloris",
    "Paralvinella sulfincola",
    "Lepetodrilus fucensis",
    "Munidopsis geyeri",
]
DECOY_EXPEDITIONS = [
    {"name": "Meridian-6", "year": 2024, "region": "East Pacific Rise"},
    {"name": "Abyssal-3", "year": 2023, "region": "Galapagos Rift"},
]
DECOY_SAMPLES = [
    {"id": "BD-1187", "species": "Calyptogena magnifica", "depth_m": 2190, "site": "Meridian-6 / Vent D1", "status": "Catalogued"},
    {"id": "BD-1193", "species": "Osedax mucofloris", "depth_m": 2205, "site": "Meridian-6 / Vent D1", "status": "Catalogued"},
    {"id": "BD-1201", "species": "Paralvinella sulfincola", "depth_m": 2166, "site": "Meridian-6 / Vent D2", "status": "Catalogued"},
    {"id": "BD-1214", "species": "Lepetodrilf fucensis", "depth_m": 2299, "site": "Meridian-6 / Vent E1", "status": "Under review"},
    {"id": "BD-1220", "species": "Munidopsis geyeri", "depth_m": 2340, "site": "Meridian-6 / Vent E2", "status": "Catalogued"},
]
DECOY_USERS = [
    {"id": "u-041", "name": "S. Delacroix", "role": "Field Technician"},
    {"id": "u-058", "name": "K. Wren", "role": "Data Curator"},
]
DECOY_CONFIG = {"db_host": "ocean-db-shard4.bluedepth.org", "backup_region": "us-east1", "encryption": "AES-256-GCM"}


def species(decoy): return DECOY_SPECIES if decoy else REAL_SPECIES
def expeditions(decoy): return DECOY_EXPEDITIONS if decoy else REAL_EXPEDITIONS
def samples(decoy): return DECOY_SAMPLES if decoy else REAL_SAMPLES
def users(decoy): return DECOY_USERS if decoy else REAL_USERS
def config(decoy): return DECOY_CONFIG if decoy else REAL_CONFIG
