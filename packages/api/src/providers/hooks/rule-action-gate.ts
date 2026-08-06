/** Scope of a policy-rule write. Structurally compatible with `ResourceScope`. */
export interface RuleWriteScope {
  projectId?: string;
  organizationId?: string;
}

/**
 * Authorizes which policy-rule actions an org may write. The default allows
 * everything; editions inject their own implementation via `createApiApp`.
 * Called by the policy-rule service, so every write path is gated in one place.
 */
export interface RuleActionGate {
  assertAllowed(scope: RuleWriteScope, actions: string[]): Promise<void>;
}

const defaultRuleActionGate: RuleActionGate = {
  assertAllowed: async () => {},
};

let _ruleActionGate: RuleActionGate = defaultRuleActionGate;

export const initRuleActionGate = (a: RuleActionGate) => {
  _ruleActionGate = a;
};

export const getRuleActionGate = (): RuleActionGate => _ruleActionGate;
