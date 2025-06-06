// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

// Export members:
export { GetMonitoredInstanceArgs, GetMonitoredInstanceResult, GetMonitoredInstanceOutputArgs } from "./getMonitoredInstance";
export const getMonitoredInstance: typeof import("./getMonitoredInstance").getMonitoredInstance = null as any;
export const getMonitoredInstanceOutput: typeof import("./getMonitoredInstance").getMonitoredInstanceOutput = null as any;
utilities.lazyLoad(exports, ["getMonitoredInstance","getMonitoredInstanceOutput"], () => require("./getMonitoredInstance"));

export { GetMonitoredInstancesArgs, GetMonitoredInstancesResult, GetMonitoredInstancesOutputArgs } from "./getMonitoredInstances";
export const getMonitoredInstances: typeof import("./getMonitoredInstances").getMonitoredInstances = null as any;
export const getMonitoredInstancesOutput: typeof import("./getMonitoredInstances").getMonitoredInstancesOutput = null as any;
utilities.lazyLoad(exports, ["getMonitoredInstances","getMonitoredInstancesOutput"], () => require("./getMonitoredInstances"));

export { MonitorPluginManagementArgs, MonitorPluginManagementState } from "./monitorPluginManagement";
export type MonitorPluginManagement = import("./monitorPluginManagement").MonitorPluginManagement;
export const MonitorPluginManagement: typeof import("./monitorPluginManagement").MonitorPluginManagement = null as any;
utilities.lazyLoad(exports, ["MonitorPluginManagement"], () => require("./monitorPluginManagement"));


const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "oci:AppMgmtControl/monitorPluginManagement:MonitorPluginManagement":
                return new MonitorPluginManagement(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("oci", "AppMgmtControl/monitorPluginManagement", _module)
