// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

// Export members:
export { GetProtectedDatabaseArgs, GetProtectedDatabaseResult, GetProtectedDatabaseOutputArgs } from "./getProtectedDatabase";
export const getProtectedDatabase: typeof import("./getProtectedDatabase").getProtectedDatabase = null as any;
export const getProtectedDatabaseOutput: typeof import("./getProtectedDatabase").getProtectedDatabaseOutput = null as any;
utilities.lazyLoad(exports, ["getProtectedDatabase","getProtectedDatabaseOutput"], () => require("./getProtectedDatabase"));

export { GetProtectedDatabaseFetchConfigurationArgs, GetProtectedDatabaseFetchConfigurationResult, GetProtectedDatabaseFetchConfigurationOutputArgs } from "./getProtectedDatabaseFetchConfiguration";
export const getProtectedDatabaseFetchConfiguration: typeof import("./getProtectedDatabaseFetchConfiguration").getProtectedDatabaseFetchConfiguration = null as any;
export const getProtectedDatabaseFetchConfigurationOutput: typeof import("./getProtectedDatabaseFetchConfiguration").getProtectedDatabaseFetchConfigurationOutput = null as any;
utilities.lazyLoad(exports, ["getProtectedDatabaseFetchConfiguration","getProtectedDatabaseFetchConfigurationOutput"], () => require("./getProtectedDatabaseFetchConfiguration"));

export { GetProtectedDatabasesArgs, GetProtectedDatabasesResult, GetProtectedDatabasesOutputArgs } from "./getProtectedDatabases";
export const getProtectedDatabases: typeof import("./getProtectedDatabases").getProtectedDatabases = null as any;
export const getProtectedDatabasesOutput: typeof import("./getProtectedDatabases").getProtectedDatabasesOutput = null as any;
utilities.lazyLoad(exports, ["getProtectedDatabases","getProtectedDatabasesOutput"], () => require("./getProtectedDatabases"));

export { GetProtectionPoliciesArgs, GetProtectionPoliciesResult, GetProtectionPoliciesOutputArgs } from "./getProtectionPolicies";
export const getProtectionPolicies: typeof import("./getProtectionPolicies").getProtectionPolicies = null as any;
export const getProtectionPoliciesOutput: typeof import("./getProtectionPolicies").getProtectionPoliciesOutput = null as any;
utilities.lazyLoad(exports, ["getProtectionPolicies","getProtectionPoliciesOutput"], () => require("./getProtectionPolicies"));

export { GetProtectionPolicyArgs, GetProtectionPolicyResult, GetProtectionPolicyOutputArgs } from "./getProtectionPolicy";
export const getProtectionPolicy: typeof import("./getProtectionPolicy").getProtectionPolicy = null as any;
export const getProtectionPolicyOutput: typeof import("./getProtectionPolicy").getProtectionPolicyOutput = null as any;
utilities.lazyLoad(exports, ["getProtectionPolicy","getProtectionPolicyOutput"], () => require("./getProtectionPolicy"));

export { GetRecoveryServiceSubnetArgs, GetRecoveryServiceSubnetResult, GetRecoveryServiceSubnetOutputArgs } from "./getRecoveryServiceSubnet";
export const getRecoveryServiceSubnet: typeof import("./getRecoveryServiceSubnet").getRecoveryServiceSubnet = null as any;
export const getRecoveryServiceSubnetOutput: typeof import("./getRecoveryServiceSubnet").getRecoveryServiceSubnetOutput = null as any;
utilities.lazyLoad(exports, ["getRecoveryServiceSubnet","getRecoveryServiceSubnetOutput"], () => require("./getRecoveryServiceSubnet"));

export { GetRecoveryServiceSubnetsArgs, GetRecoveryServiceSubnetsResult, GetRecoveryServiceSubnetsOutputArgs } from "./getRecoveryServiceSubnets";
export const getRecoveryServiceSubnets: typeof import("./getRecoveryServiceSubnets").getRecoveryServiceSubnets = null as any;
export const getRecoveryServiceSubnetsOutput: typeof import("./getRecoveryServiceSubnets").getRecoveryServiceSubnetsOutput = null as any;
utilities.lazyLoad(exports, ["getRecoveryServiceSubnets","getRecoveryServiceSubnetsOutput"], () => require("./getRecoveryServiceSubnets"));

export { ProtectedDatabaseArgs, ProtectedDatabaseState } from "./protectedDatabase";
export type ProtectedDatabase = import("./protectedDatabase").ProtectedDatabase;
export const ProtectedDatabase: typeof import("./protectedDatabase").ProtectedDatabase = null as any;
utilities.lazyLoad(exports, ["ProtectedDatabase"], () => require("./protectedDatabase"));

export { ProtectionPolicyArgs, ProtectionPolicyState } from "./protectionPolicy";
export type ProtectionPolicy = import("./protectionPolicy").ProtectionPolicy;
export const ProtectionPolicy: typeof import("./protectionPolicy").ProtectionPolicy = null as any;
utilities.lazyLoad(exports, ["ProtectionPolicy"], () => require("./protectionPolicy"));

export { RecoveryServiceSubnetArgs, RecoveryServiceSubnetState } from "./recoveryServiceSubnet";
export type RecoveryServiceSubnet = import("./recoveryServiceSubnet").RecoveryServiceSubnet;
export const RecoveryServiceSubnet: typeof import("./recoveryServiceSubnet").RecoveryServiceSubnet = null as any;
utilities.lazyLoad(exports, ["RecoveryServiceSubnet"], () => require("./recoveryServiceSubnet"));


const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "oci:RecoveryMod/protectedDatabase:ProtectedDatabase":
                return new ProtectedDatabase(name, <any>undefined, { urn })
            case "oci:RecoveryMod/protectionPolicy:ProtectionPolicy":
                return new ProtectionPolicy(name, <any>undefined, { urn })
            case "oci:RecoveryMod/recoveryServiceSubnet:RecoveryServiceSubnet":
                return new RecoveryServiceSubnet(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("oci", "RecoveryMod/protectedDatabase", _module)
pulumi.runtime.registerResourceModule("oci", "RecoveryMod/protectionPolicy", _module)
pulumi.runtime.registerResourceModule("oci", "RecoveryMod/recoveryServiceSubnet", _module)