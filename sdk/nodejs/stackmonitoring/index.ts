// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

// Export members:
export * from "./discoveryJob";
export * from "./getDiscoveryJob";
export * from "./getDiscoveryJobLogs";
export * from "./getDiscoveryJobs";
export * from "./getMonitoredResource";
export * from "./monitoredResource";
export * from "./monitoredResourcesAssociateMonitoredResource";
export * from "./monitoredResourcesListMember";
export * from "./monitoredResourcesSearch";
export * from "./monitoredResourcesSearchAssociation";

// Import resources to register:
import { DiscoveryJob } from "./discoveryJob";
import { MonitoredResource } from "./monitoredResource";
import { MonitoredResourcesAssociateMonitoredResource } from "./monitoredResourcesAssociateMonitoredResource";
import { MonitoredResourcesListMember } from "./monitoredResourcesListMember";
import { MonitoredResourcesSearch } from "./monitoredResourcesSearch";
import { MonitoredResourcesSearchAssociation } from "./monitoredResourcesSearchAssociation";

const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "oci:StackMonitoring/discoveryJob:DiscoveryJob":
                return new DiscoveryJob(name, <any>undefined, { urn })
            case "oci:StackMonitoring/monitoredResource:MonitoredResource":
                return new MonitoredResource(name, <any>undefined, { urn })
            case "oci:StackMonitoring/monitoredResourcesAssociateMonitoredResource:MonitoredResourcesAssociateMonitoredResource":
                return new MonitoredResourcesAssociateMonitoredResource(name, <any>undefined, { urn })
            case "oci:StackMonitoring/monitoredResourcesListMember:MonitoredResourcesListMember":
                return new MonitoredResourcesListMember(name, <any>undefined, { urn })
            case "oci:StackMonitoring/monitoredResourcesSearch:MonitoredResourcesSearch":
                return new MonitoredResourcesSearch(name, <any>undefined, { urn })
            case "oci:StackMonitoring/monitoredResourcesSearchAssociation:MonitoredResourcesSearchAssociation":
                return new MonitoredResourcesSearchAssociation(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("oci", "StackMonitoring/discoveryJob", _module)
pulumi.runtime.registerResourceModule("oci", "StackMonitoring/monitoredResource", _module)
pulumi.runtime.registerResourceModule("oci", "StackMonitoring/monitoredResourcesAssociateMonitoredResource", _module)
pulumi.runtime.registerResourceModule("oci", "StackMonitoring/monitoredResourcesListMember", _module)
pulumi.runtime.registerResourceModule("oci", "StackMonitoring/monitoredResourcesSearch", _module)
pulumi.runtime.registerResourceModule("oci", "StackMonitoring/monitoredResourcesSearchAssociation", _module)