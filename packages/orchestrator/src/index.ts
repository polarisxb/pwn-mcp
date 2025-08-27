import { BinaryFacts, StrategyPlan } from "@pwn-mcp/core";

export interface DecisionEngine {
  planFromFacts(facts: BinaryFacts): StrategyPlan;
}

export class SimpleDecisionEngine implements DecisionEngine {
  planFromFacts(facts: BinaryFacts): StrategyPlan {
    const steps = [] as StrategyPlan["steps"];
    steps.push({ name: "static-overview", description: "Review protections and I/O hints" });
    if (facts.protections.NX && facts.protections.PIE) {
      steps.push({ name: "leak-libc", description: "Leak libc via GOT/PLT" });
      steps.push({ name: "compute-base", description: "Resolve base and symbols" });
    }
    steps.push({ name: "measure-offset", description: "Run cyclic and compute offset" });
    steps.push({ name: "generate-scaffold", description: "Generate pwntools template with TODOs" });
    return { steps };
  }
}

export default SimpleDecisionEngine; 