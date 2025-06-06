// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

// Export members:
export { GetRuleArgs, GetRuleResult, GetRuleOutputArgs } from "./getRule";
export const getRule: typeof import("./getRule").getRule = null as any;
export const getRuleOutput: typeof import("./getRule").getRuleOutput = null as any;
utilities.lazyLoad(exports, ["getRule","getRuleOutput"], () => require("./getRule"));

export { GetRulesArgs, GetRulesResult, GetRulesOutputArgs } from "./getRules";
export const getRules: typeof import("./getRules").getRules = null as any;
export const getRulesOutput: typeof import("./getRules").getRulesOutput = null as any;
utilities.lazyLoad(exports, ["getRules","getRulesOutput"], () => require("./getRules"));

export { RuleArgs, RuleState } from "./rule";
export type Rule = import("./rule").Rule;
export const Rule: typeof import("./rule").Rule = null as any;
utilities.lazyLoad(exports, ["Rule"], () => require("./rule"));


const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "oci:Events/rule:Rule":
                return new Rule(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("oci", "Events/rule", _module)
