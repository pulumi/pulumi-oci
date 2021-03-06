// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

// Export members:
export * from "./application";
export * from "./function";
export * from "./getApplication";
export * from "./getApplications";
export * from "./getFunction";
export * from "./getFunctions";
export * from "./invokeFunction";

// Import resources to register:
import { Application } from "./application";
import { Function } from "./function";
import { InvokeFunction } from "./invokeFunction";

const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "oci:Functions/application:Application":
                return new Application(name, <any>undefined, { urn })
            case "oci:Functions/function:Function":
                return new Function(name, <any>undefined, { urn })
            case "oci:Functions/invokeFunction:InvokeFunction":
                return new InvokeFunction(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("oci", "Functions/application", _module)
pulumi.runtime.registerResourceModule("oci", "Functions/function", _module)
pulumi.runtime.registerResourceModule("oci", "Functions/invokeFunction", _module)
