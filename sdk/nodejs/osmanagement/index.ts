// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

// Export members:
export * from "./getManagedInstance";
export * from "./getManagedInstanceEventReport";
export * from "./getManagedInstanceGroup";
export * from "./getManagedInstanceGroups";
export * from "./getManagedInstances";
export * from "./getSoftwareSource";
export * from "./getSoftwareSources";
export * from "./managedInstance";
export * from "./managedInstanceGroup";
export * from "./managedInstanceManagement";
export * from "./softwareSource";

// Import resources to register:
import { ManagedInstance } from "./managedInstance";
import { ManagedInstanceGroup } from "./managedInstanceGroup";
import { ManagedInstanceManagement } from "./managedInstanceManagement";
import { SoftwareSource } from "./softwareSource";

const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "oci:OsManagement/managedInstance:ManagedInstance":
                return new ManagedInstance(name, <any>undefined, { urn })
            case "oci:OsManagement/managedInstanceGroup:ManagedInstanceGroup":
                return new ManagedInstanceGroup(name, <any>undefined, { urn })
            case "oci:OsManagement/managedInstanceManagement:ManagedInstanceManagement":
                return new ManagedInstanceManagement(name, <any>undefined, { urn })
            case "oci:OsManagement/softwareSource:SoftwareSource":
                return new SoftwareSource(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("oci", "OsManagement/managedInstance", _module)
pulumi.runtime.registerResourceModule("oci", "OsManagement/managedInstanceGroup", _module)
pulumi.runtime.registerResourceModule("oci", "OsManagement/managedInstanceManagement", _module)
pulumi.runtime.registerResourceModule("oci", "OsManagement/softwareSource", _module)
