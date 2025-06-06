// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

// Export members:
export { GetInstVbsInstanceArgs, GetInstVbsInstanceResult, GetInstVbsInstanceOutputArgs } from "./getInstVbsInstance";
export const getInstVbsInstance: typeof import("./getInstVbsInstance").getInstVbsInstance = null as any;
export const getInstVbsInstanceOutput: typeof import("./getInstVbsInstance").getInstVbsInstanceOutput = null as any;
utilities.lazyLoad(exports, ["getInstVbsInstance","getInstVbsInstanceOutput"], () => require("./getInstVbsInstance"));

export { GetInstVbsInstancesArgs, GetInstVbsInstancesResult, GetInstVbsInstancesOutputArgs } from "./getInstVbsInstances";
export const getInstVbsInstances: typeof import("./getInstVbsInstances").getInstVbsInstances = null as any;
export const getInstVbsInstancesOutput: typeof import("./getInstVbsInstances").getInstVbsInstancesOutput = null as any;
utilities.lazyLoad(exports, ["getInstVbsInstances","getInstVbsInstancesOutput"], () => require("./getInstVbsInstances"));

export { InstVbsInstanceArgs, InstVbsInstanceState } from "./instVbsInstance";
export type InstVbsInstance = import("./instVbsInstance").InstVbsInstance;
export const InstVbsInstance: typeof import("./instVbsInstance").InstVbsInstance = null as any;
utilities.lazyLoad(exports, ["InstVbsInstance"], () => require("./instVbsInstance"));


const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "oci:Vbs/instVbsInstance:InstVbsInstance":
                return new InstVbsInstance(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("oci", "Vbs/instVbsInstance", _module)
