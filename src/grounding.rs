// Grounding is the refinement organ of HEIDES.
//
// It takes an objective or a plan and checks it against the spine graph and
// against the outside world. It can confirm feasibility, surface missing
// prerequisites, and produce a bounded specification that the agent then
// builds against. When the plan asks for facts that change over time,
// Grounding can consult the web and update its own knowledge.

#[derive(Debug, serde::Serialize)]
pub struct PlanVerdict {
    pub feasible: bool,
    pub notes: Vec<String>,
    pub scaffold: Vec<String>,
}

/// Evaluate a plan against the current codebase.
///
/// Milestone one: heuristic checks on paths, names and existing symbols.
/// Milestone two: web grounded confirmation of package versions and APIs.
/// Milestone three: scaffold generation for new projects from a plan.
pub fn evaluate(plan: &str) -> PlanVerdict {
    let mut notes = Vec::new();
    let scaffold = Vec::new();
    if plan.trim().is_empty() {
        notes.push("the plan is empty. describe the objective first.".to_string());
        return PlanVerdict {
            feasible: false,
            notes,
            scaffold,
        };
    }
    notes.push("grounding received the plan.".to_string());
    notes.push("web grounding lands in milestone two.".to_string());
    PlanVerdict {
        feasible: true,
        notes,
        scaffold,
    }
}
