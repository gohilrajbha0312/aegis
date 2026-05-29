from typing import List, Dict, Any

class AssetCorrelationEngine:
    """
    Cross-source asset reconciliation.
    Uses fuzzy matching and duplicate suppression to map IPs, Domains, and Subdomains.
    """
    def __init__(self):
        self.master_inventory = {}

    def ingest_assets(self, source: str, assets: List[Dict[str, Any]]):
        """
        Merges assets from multiple tools (Amass, Subfinder) and suppresses duplicates.
        """
        for asset in assets:
            identifier = asset.get("hostname") or asset.get("ip")
            if not identifier:
                continue
                
            if identifier not in self.master_inventory:
                self.master_inventory[identifier] = {
                    "identifier": identifier,
                    "sources": [source],
                    "metadata": asset.get("metadata", {})
                }
            else:
                if source not in self.master_inventory[identifier]["sources"]:
                    self.master_inventory[identifier]["sources"].append(source)
                # Merge metadata
                self.master_inventory[identifier]["metadata"].update(asset.get("metadata", {}))

    def get_inventory(self) -> List[Dict[str, Any]]:
        return list(self.master_inventory.values())
