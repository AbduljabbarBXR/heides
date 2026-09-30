// The resolved dependency graph.
//
// A flat list of installed packages answers "is lodash 4.17.19 in this
// project", which is the wrong question. The one that matters is "is it in my
// build", and a package four levels down is reached through an edge nobody
// declared in a manifest. Every lockfile in common use already carries those
// edges; the question is whether anyone reads them.
//
// Depth is only useful if it is honest, so the rules are strict. A package with
// no path from a direct dependency is unreachable, not depth zero, and is
// carried without a depth rather than being dropped: it is present in the
// lockfile and an advisory on it is real, but nothing in the build reaches it,
// and conflating the two is how a tool teaches an agent to ignore it.

use std::collections::{HashMap, HashSet, VecDeque};

/// One resolved package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockNode {
    pub name: String,
    pub version: String,
    pub ecosystem: &'static str,
    /// Hops from a direct dependency. `None` when nothing in the build reaches
    /// this package, which is a real state after a bad merge and not an error.
    pub depth: Option<u64>,
    /// A dev-only dependency. Present in the lock, not in the shipped build.
    pub dev: bool,
    /// The path taken from a direct dependency, for reporting how a package is
    /// reached. Empty when unreachable.
    pub path: Vec<String>,
}

/// A resolved dependency graph for one lockfile.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LockGraph {
    pub nodes: Vec<LockNode>,
    /// Edges as `from -> to`, both package names.
    pub edges: Vec<(String, String)>,
    /// Which lockfile produced this, for a finding to be grounded in.
    pub source: String,
    /// Names listed as direct dependencies in the manifest, used to seed the
    /// walk. Empty means "everything is direct", which is the correct reading of
    /// a lockfile with no separate manifest.
    pub direct: Vec<String>,
}

impl LockGraph {
    /// A graph with nodes and no edges: every package is direct. This is what a
    /// lockfile with no edge information yields, and it must not be discarded.
    pub fn flat(packages: Vec<LockNode>, ecosystem: &'static str, source: &str) -> LockGraph {
        let nodes = packages
            .into_iter()
            .map(|mut p| {
                p.ecosystem = ecosystem;
                p.depth = Some(1);
                p.path = vec![p.name.clone()];
                p
            })
            .collect();
        LockGraph {
            nodes,
            edges: Vec::new(),
            source: source.to_string(),
            direct: Vec::new(),
        }
    }

    pub fn node(&self, name: &str) -> Option<&LockNode> {
        self.nodes.iter().find(|n| n.name == name)
    }

    pub fn names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.nodes.iter().map(|n| n.name.clone()).collect();
        v.sort();
        v
    }

    /// Resolve every node's depth and path by breadth first from the direct
    /// dependencies.
    ///
    /// Breadth first rather than depth first because the interesting number is
    /// the shortest distance from the build, and a deep walk would report a
    /// longer path to a package that is also reachable in one hop. A visited set
    /// makes a cyclic lockfile terminate.
    pub fn resolve(&mut self) {
        if self.edges.is_empty() {
            // No edges means the lockfile carries no dependency information, not
            // that nothing is reachable. Returning early left every node with
            // depth None, which reads as "nothing here is in the build" and is
            // the opposite of the truth. Every package is a root at depth one,
            // and it is the manifest that can say otherwise.
            for n in self.nodes.iter_mut() {
                n.depth = Some(1);
                n.path = vec![n.name.clone()];
            }
            return;
        }
        let mut out_edges: HashMap<&str, Vec<&str>> = HashMap::new();
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        for n in &self.nodes {
            in_degree.insert(n.name.as_str(), 0);
        }
        for (from, to) in &self.edges {
            if !in_degree.contains_key(from.as_str()) || !in_degree.contains_key(to.as_str()) {
                continue;
            }
            out_edges
                .entry(from.as_str())
                .or_default()
                .push(to.as_str());
            *in_degree.get_mut(to.as_str()).expect("checked above") += 1;
        }

        // Roots: the manifest's direct dependencies when we have them. Failing
        // that, a node nothing else depends on.
        //
        // The fallback has to be used carefully, and the original version was
        // wrong in a way the tests caught. In an npm lockfileVersion 1 every
        // package is a sibling, and a package that is both top-level and a
        // dependency of nothing still has an incoming edge from its parent, so
        // in-degree is what separates them. The bug was seeding from every
        // zero-in-degree node, which made a sibling of a direct dependency look
        // direct too, and reported depth 1 for everything.
        let mut roots: Vec<String> = self.direct.clone();
        roots.retain(|d| in_degree.contains_key(d.as_str()));
        if roots.is_empty() {
            roots = in_degree
                .iter()
                .filter(|(_, deg)| **deg == 0)
                .map(|(name, _)| (*name).to_string())
                .collect();
        }

        let mut depth: HashMap<String, u64> = HashMap::new();
        let mut path: HashMap<String, Vec<String>> = HashMap::new();
        let mut queue: VecDeque<(String, u64, Vec<String>)> = VecDeque::new();
        for r in roots {
            if depth.contains_key(&r) {
                continue;
            }
            depth.insert(r.clone(), 1);
            path.insert(r.clone(), vec![r.clone()]);
            queue.push_back((r, 1, vec![]));
        }
        // A stable order, so the reported path does not change between runs.
        let mut pending: Vec<(String, u64, Vec<String>)> = queue.drain(..).collect();
        pending.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, d, _) in pending {
            queue.push_back((name, d, Vec::new()));
        }

        while let Some((name, d, trail)) = queue.pop_front() {
            // The stored path for `name` is already the root through `name`, so a
            // child extends it by this node. Building the trail from the
            // accumulator instead truncated the last hop, which reported
            // [a, b] for a node named c.
            let next_trail = match path.get(&name) {
                Some(p) if !p.is_empty() => p.clone(),
                _ => trail,
            };
            let Some(children) = out_edges.get(name.as_str()) else {
                continue;
            };
            let mut kids: Vec<&&str> = children.iter().collect();
            kids.sort();
            for kid in kids {
                if depth.contains_key(*kid) {
                    continue;
                }
                depth.insert((*kid).to_string(), d + 1);
                // The child's path is the parent's path plus the child itself.
                // Storing the parent's path unchanged is what reported
                // [a, b] for a node named c.
                let mut child_path = next_trail.clone();
                child_path.push((*kid).to_string());
                path.insert((*kid).to_string(), child_path.clone());
                queue.push_back(((*kid).to_string(), d + 1, child_path));
            }
        }

        for n in self.nodes.iter_mut() {
            n.depth = depth.get(&n.name).copied();
            n.path = path.get(&n.name).cloned().unwrap_or_default();
        }
    }

    /// The path from a direct dependency to `name`, empty when unreachable.
    pub fn path_to(&self, name: &str) -> Option<Vec<String>> {
        self.node(name)
            .map(|n| n.path.clone())
            .filter(|p| !p.is_empty())
    }

    /// The flat dependency list, for the existing advisory and outdated checks.
    ///
    /// Unreachable packages are included. An advisory on a package nothing
    /// reaches is worth seeing; the depth is what tells the reader how much it
    /// matters, and dropping it would lose the finding entirely.
    pub fn to_dependencies(&self) -> Vec<crate::deps::Dependency> {
        self.nodes
            .iter()
            .map(|n| crate::deps::Dependency {
                name: n.name.clone(),
                version: n.version.clone(),
                ecosystem: n.ecosystem,
            })
            .collect()
    }

    /// How many packages are reachable, and how many are not.
    pub fn reachability(&self) -> (usize, usize) {
        let (mut reachable, mut orphan) = (0, 0);
        for n in &self.nodes {
            if n.depth.is_some() {
                reachable += 1;
            } else {
                orphan += 1;
            }
        }
        (reachable, orphan)
    }

    /// The packages at or beyond `depth`, deepest first. This is the answer to
    /// "what only exists because of something I pulled in".
    pub fn deepest(&self, at_least: u64) -> Vec<&LockNode> {
        let mut v: Vec<&LockNode> = self
            .nodes
            .iter()
            .filter(|n| n.depth.map(|d| d >= at_least).unwrap_or(false))
            .collect();
        v.sort_by(|a, b| b.depth.cmp(&a.depth).then(a.name.cmp(&b.name)));
        v
    }

    /// Distinct names, for a caller that has merged several lockfiles.
    pub fn into_names(self) -> HashSet<String> {
        self.nodes.into_iter().map(|n| n.name).collect()
    }
}
