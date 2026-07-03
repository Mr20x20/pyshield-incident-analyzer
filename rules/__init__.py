# rules package
from rules import brute_force, privilege_escalation, new_account, lateral_movement

ALL_RULES = [
    brute_force,
    privilege_escalation,
    new_account,
    lateral_movement,
]
