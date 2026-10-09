"""解析。文脈の組み立て、LLM の呼び出し、出力の検証、解析の記録、事例カード。

後続の計画（画面、配置）が使う入口は、ここから取り込む。
"""
from tia.analysis.records import PHASES, STATUSES, TRIGGERS

__all__ = ["PHASES", "STATUSES", "TRIGGERS"]
