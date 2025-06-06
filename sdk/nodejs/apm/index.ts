// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

// Export members:
export { ApmDomainArgs, ApmDomainState } from "./apmDomain";
export type ApmDomain = import("./apmDomain").ApmDomain;
export const ApmDomain: typeof import("./apmDomain").ApmDomain = null as any;
utilities.lazyLoad(exports, ["ApmDomain"], () => require("./apmDomain"));

export { GetApmDomainArgs, GetApmDomainResult, GetApmDomainOutputArgs } from "./getApmDomain";
export const getApmDomain: typeof import("./getApmDomain").getApmDomain = null as any;
export const getApmDomainOutput: typeof import("./getApmDomain").getApmDomainOutput = null as any;
utilities.lazyLoad(exports, ["getApmDomain","getApmDomainOutput"], () => require("./getApmDomain"));

export { GetApmDomainsArgs, GetApmDomainsResult, GetApmDomainsOutputArgs } from "./getApmDomains";
export const getApmDomains: typeof import("./getApmDomains").getApmDomains = null as any;
export const getApmDomainsOutput: typeof import("./getApmDomains").getApmDomainsOutput = null as any;
utilities.lazyLoad(exports, ["getApmDomains","getApmDomainsOutput"], () => require("./getApmDomains"));

export { GetDataKeysArgs, GetDataKeysResult, GetDataKeysOutputArgs } from "./getDataKeys";
export const getDataKeys: typeof import("./getDataKeys").getDataKeys = null as any;
export const getDataKeysOutput: typeof import("./getDataKeys").getDataKeysOutput = null as any;
utilities.lazyLoad(exports, ["getDataKeys","getDataKeysOutput"], () => require("./getDataKeys"));


const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "oci:Apm/apmDomain:ApmDomain":
                return new ApmDomain(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("oci", "Apm/apmDomain", _module)
