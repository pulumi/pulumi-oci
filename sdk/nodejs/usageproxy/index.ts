// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

// Export members:
export * from "./getSubscriptionProduct";
export * from "./getSubscriptionProducts";
export * from "./getSubscriptionRedeemableUser";
export * from "./getSubscriptionRedeemableUsers";
export * from "./getSubscriptionReward";
export * from "./getSubscriptionRewards";
export * from "./subscriptionRedeemableUser";

// Import resources to register:
import { SubscriptionRedeemableUser } from "./subscriptionRedeemableUser";

const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "oci:UsageProxy/subscriptionRedeemableUser:SubscriptionRedeemableUser":
                return new SubscriptionRedeemableUser(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("oci", "UsageProxy/subscriptionRedeemableUser", _module)
