// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

// Export members:
export * from "./appAcceleration";
export * from "./appAccelerationPolicy";
export * from "./getAppAcceleration";
export * from "./getAppAccelerationPolicies";
export * from "./getAppAccelerationPolicy";
export * from "./getAppAccelerations";

// Import resources to register:
import { AppAcceleration } from "./appAcceleration";
import { AppAccelerationPolicy } from "./appAccelerationPolicy";

const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "oci:Waa/appAcceleration:AppAcceleration":
                return new AppAcceleration(name, <any>undefined, { urn })
            case "oci:Waa/appAccelerationPolicy:AppAccelerationPolicy":
                return new AppAccelerationPolicy(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("oci", "Waa/appAcceleration", _module)
pulumi.runtime.registerResourceModule("oci", "Waa/appAccelerationPolicy", _module)