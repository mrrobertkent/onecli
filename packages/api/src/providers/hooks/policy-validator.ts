import type { PolicyTargetInput } from "../../validations/policy";

export interface PolicyValidator {
  validate(
    organizationId: string,
    provider: string,
    metadata: Record<string, unknown> | null,
    policy: Record<string, unknown>,
  ): Promise<void>;
  /**
   * Edition gate over a rule's targets, run on create/update but never on
   * publish, so a pre-existing row cannot brick a whole-scope publish. Absent is
   * permissive.
   */
  validateTargets?(targets: PolicyTargetInput[]): Promise<void>;
}

const defaultPolicyValidator: PolicyValidator = {
  validate: async () => {},
};

let _policyValidator: PolicyValidator = defaultPolicyValidator;

export const initPolicyValidator = (v: PolicyValidator) => {
  _policyValidator = v;
};

export const getPolicyValidator = (): PolicyValidator => _policyValidator;
