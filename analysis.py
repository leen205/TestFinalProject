# analysis.py
# -*- coding: utf-8 -*-
"""
Digital Forensics Analyzer (analysis.py)
Enhanced version for correct risk classification.
Author: Leen Ajlan
"""

import os
import re
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("analysis.log", encoding="utf-8"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# -------------------------
# Config / thresholds
# -------------------------
class Config:
    SUPPORTED_EXTENSIONS = {".log", ".txt", ".csv"}
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
    DEFAULT_RULES_FILE = "rules.json"
    RISK_THRESHOLDS = {"HIGH": 20, "MEDIUM": 10, "LOW": 0}

# -------------------------
# Rule management
# -------------------------
class RuleManager:
    def __init__(self, rules_file: Optional[str] = None):
        self.rules_file = rules_file or Config.DEFAULT_RULES_FILE
        self.rules = self._load_rules()

    def _load_rules(self) -> Dict[str, List[Dict[str, Any]]]:
        if os.path.exists(self.rules_file):
            try:
                with open(self.rules_file, "r", encoding="utf-8") as f:
                    j = json.load(f)
                if not isinstance(j, dict):
                    logger.warning("Rules file format unexpected — using defaults.")
                    return self._default_rules()
                logger.info(f"Loaded rules from {self.rules_file}")
                return j
            except Exception as e:
                logger.error(f"Failed to load rules: {e}. Using defaults.")
                return self._default_rules()
        else:
            logger.info(f"No rules file found at {self.rules_file}; using defaults.")
            return self._default_rules()

    def _default_rules(self) -> Dict[str, List[Dict[str, Any]]]:
        return {
            "high_risk_patterns": [
                {
                    "name": "SQL Injection",
                    "pattern": r"\b(select\s+.+?\s+from\b|union\s+select|exec\s+)\b",
                    "description": "Possible SQL injection pattern",
                    "score": 10,
                    "category": "Application Attack",
                },
                {
                    "name": "Ransomware",
                    "pattern": r"\bransomware\b|\bencrypted\s+files\b|\.locked\b",
                    "description": "Possible ransomware activity",
                    "score": 10,
                    "category": "Malware",
                },
            ],
            "medium_risk_patterns": [
                {
                    "name": "Failed Login",
                    "pattern": r"failed\s+login|authentication\s+failure|invalid\s+user",
                    "description": "Failed authentication attempts",
                    "score": 5,
                    "category": "Authentication",
                },
                {
                    "name": "Suspicious Download",
                    "pattern": r"https?://[^\s]+/.*(exe|scr|zip|rar)",
                    "description": "Possible executable download",
                    "score": 5,
                    "category": "Network",
                },
            ],
            "low_risk_patterns": [
                {
                    "name": "Warning",
                    "pattern": r"\bwarning\b",
                    "description": "System warning event",
                    "score": 1,
                    "category": "Info",
                },
            ],
        }

    def get_rules(self) -> Dict[str, List[Dict[str, Any]]]:
        return self.rules

# -------------------------
# File manager
# -------------------------
class FileManager:
    @staticmethod
    def read_file(path: str) -> str:
        if not os.path.exists(path):
            raise FileNotFoundError(f"File not found: {path}")
        size = os.path.getsize(path)
        if size > Config.MAX_FILE_SIZE:
            raise ValueError(f"File too large: {size} bytes (limit {Config.MAX_FILE_SIZE})")
        encodings = ["utf-8", "latin-1", "utf-16"]
        last_exc = None
        for enc in encodings:
            try:
                with open(path, "r", encoding=enc) as f:
                    return f.read()
            except Exception as e:
                last_exc = e
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()

# -------------------------
# Analyzer core
# -------------------------
class ForensicAnalyzer:
    def __init__(self, rules_file: Optional[str] = None):
        self.rule_manager = RuleManager(rules_file)
        self.file_manager = FileManager()

    def analyze_log_basic(self, content: str) -> Dict[str, Any]:
        lines = content.splitlines()
        errors = sum(1 for l in lines if re.search(r"\berror\b", l, re.IGNORECASE))
        warnings = sum(1 for l in lines if re.search(r"\bwarning\b", l, re.IGNORECASE))
        infos = sum(1 for l in lines if re.search(r"\binfo\b", l, re.IGNORECASE))
        return {
            "total_lines": len(lines),
            "errors": errors,
            "warnings": warnings,
            "info_events": infos,
            "analysis_timestamp": datetime.utcnow().isoformat() + "Z",
        }

    def search_suspicious_patterns(self, content: str) -> List[Dict[str, Any]]:
        rules = self.rule_manager.get_rules()
        found: List[Dict[str, Any]] = []
        mapping = {
            "high_risk_patterns": {"icon": "[!]", "level": "عالي الخطورة", "color": "red"},
            "medium_risk_patterns": {"icon": "[~]", "level": "متوسط الخطورة", "color": "orange"},
            "low_risk_patterns": {"icon": "[✓]", "level": "منخفض الخطورة", "color": "green"},
        }

        for category_key, meta in mapping.items():
            for rule in rules.get(category_key, []):
                pattern = rule.get("pattern")
                # تجاهل أسطر INFO وDEBUG
                lines = content.splitlines()
                filtered_lines = [l for l in lines if not re.search(r"\b(INFO|DEBUG)\b", l, re.IGNORECASE)]
                for line in filtered_lines:
                    try:
                        matches = re.findall(pattern, line, flags=re.IGNORECASE)
                    except re.error as e:
                        logger.error(f"Invalid regex '{pattern}' in rule '{rule.get('name')}' - {e}")
                        continue
                    if matches:
                        examples = matches[:5]
                        found.append({
                            "risk_icon": meta["icon"],
                            "risk_level": meta["level"],
                            "name": rule.get("name", "Unnamed"),
                            "pattern": pattern,
                            "count": len(matches),
                            "score": int(rule.get("score", 1)),
                            "description": rule.get("description", ""),
                            "category": rule.get("category", ""),
                            "examples": examples,
                        })
        # ترتيب حسب الخطورة والعدد
        found.sort(key=lambda x: (x["score"], x["count"]), reverse=True)
        return found

    def advanced_statistical_analysis(self, content: str) -> Dict[str, Any]:
        lines = content.splitlines()
        suspicious = self.search_suspicious_patterns(content)
        total_risk_score = sum(item["score"] * item["count"] for item in suspicious)

        # تحديد مستوى الخطورة
        if total_risk_score >= Config.RISK_THRESHOLDS["HIGH"]:
            overall_risk = "🟥 عالي"
            action_required = "نعم - تدخل فوري مطلوب"
        elif total_risk_score >= Config.RISK_THRESHOLDS["MEDIUM"]:
            overall_risk = "🟨 متوسط"
            action_required = "مراقبة مستمرة"
        else:
            overall_risk = "🟩 منخفض / ✅ سليم"
            action_required = "لا - الملف سليم"

        return {
            "تقييم_الخطورة": {
                "نقاط_الخطورة_الإجمالية": total_risk_score,
                "مستوى_الخطورة_الشامل": overall_risk,
                "يتطلب_تدخل": action_required,
                "عدد_التهديدات_المكتشفة": len(suspicious),
            },
            "إحصائيات_العامة": {
                "إجمالي_الأحداث": len(lines),
            },
        }

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        content = self.file_manager.read_file(file_path)
        basic = self.analyze_log_basic(content)
        suspicious = self.search_suspicious_patterns(content)
        advanced = self.advanced_statistical_analysis(content)
        return {"basic_analysis": basic, "suspicious_items": suspicious, "advanced_stats": advanced}

# -------------------------
# Module-level convenience function
# -------------------------
def analyze_file(file_path: str) -> Dict[str, Any]:
    analyzer = ForensicAnalyzer()
    return analyzer.analyze_file(file_path)

# -------------------------
# CLI demo
# -------------------------
if __name__ == "__main__":
    print("Digital Forensics Analyzer - demo run")
    sample = input("Enter path to log file (or press Enter to use 'data/sample_log.txt'): ").strip()
    if not sample:
        sample = "data/sample_log.txt"
    try:
        res = analyze_file(sample)
        import pprint
        pprint.pprint(res)
        out_dir = "results"
        os.makedirs(out_dir, exist_ok=True)
        summary_file = os.path.join(out_dir, f"analysis_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(summary_file, "w", encoding="utf-8") as f:
            json.dump(res, f, ensure_ascii=False, indent=2)
        print(f"\nAnalysis saved to {summary_file}")
    except Exception as e:
        logger.exception("Analysis failed: %s", e)
        print("Analysis failed:", e)
