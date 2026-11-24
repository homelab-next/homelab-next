---
group: Fixed
---
the SIEM role names each compiled Sigma bundle rules/zz-sigma-<n>.xml again: the first live deploy staged a literal zz-sigma-\1.xml (a backreference doubled inside a folded scalar) and stopped before the load; a test now runs the role's Sigma tasks with a stand-in hnx and checks every name the stage copies exists.
