// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

// Export members:
export * from "./export";
export * from "./exportSet";
export * from "./fileSystem";
export * from "./getExportSets";
export * from "./getExports";
export * from "./getFileSystems";
export * from "./getMountTargets";
export * from "./getSnapshot";
export * from "./getSnapshots";
export * from "./mountTarget";
export * from "./snapshot";

// Import resources to register:
import { Export } from "./export";
import { ExportSet } from "./exportSet";
import { FileSystem } from "./fileSystem";
import { MountTarget } from "./mountTarget";
import { Snapshot } from "./snapshot";

const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "oci:FileStorage/export:Export":
                return new Export(name, <any>undefined, { urn })
            case "oci:FileStorage/exportSet:ExportSet":
                return new ExportSet(name, <any>undefined, { urn })
            case "oci:FileStorage/fileSystem:FileSystem":
                return new FileSystem(name, <any>undefined, { urn })
            case "oci:FileStorage/mountTarget:MountTarget":
                return new MountTarget(name, <any>undefined, { urn })
            case "oci:FileStorage/snapshot:Snapshot":
                return new Snapshot(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("oci", "FileStorage/export", _module)
pulumi.runtime.registerResourceModule("oci", "FileStorage/exportSet", _module)
pulumi.runtime.registerResourceModule("oci", "FileStorage/fileSystem", _module)
pulumi.runtime.registerResourceModule("oci", "FileStorage/mountTarget", _module)
pulumi.runtime.registerResourceModule("oci", "FileStorage/snapshot", _module)