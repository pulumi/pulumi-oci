// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

declare var exports: any;
const __config = new pulumi.Config("oci");

/**
 * (Optional) The type of auth to use. Options are 'ApiKey', 'SecurityToken', 'InstancePrincipal', 'ResourcePrincipal' and
 * 'OKEWorkloadIdentity'. By default, 'ApiKey' will be used.
 */
export declare const auth: string | undefined;
Object.defineProperty(exports, "auth", {
    get() {
        return __config.get("auth");
    },
    enumerable: true,
});

/**
 * (Optional) The profile name to be used from config file, if not set it will be DEFAULT.
 */
export declare const configFileProfile: string | undefined;
Object.defineProperty(exports, "configFileProfile", {
    get() {
        return __config.get("configFileProfile");
    },
    enumerable: true,
});

/**
 * (Optional) Disable automatic retries for retriable errors. Automatic retries were introduced to solve some eventual
 * consistency problems but it also introduced performance issues on destroy operations.
 */
export declare const disableAutoRetries: boolean | undefined;
Object.defineProperty(exports, "disableAutoRetries", {
    get() {
        return __config.getObject<boolean>("disableAutoRetries");
    },
    enumerable: true,
});

/**
 * (Optional) The fingerprint for the user's RSA key. This can be found in user settings in the Oracle Cloud Infrastructure
 * console. Required if auth is set to 'ApiKey', ignored otherwise.
 */
export declare const fingerprint: string | undefined;
Object.defineProperty(exports, "fingerprint", {
    get() {
        return __config.get("fingerprint");
    },
    enumerable: true,
});

export declare const ignoreDefinedTags: string[] | undefined;
Object.defineProperty(exports, "ignoreDefinedTags", {
    get() {
        return __config.getObject<string[]>("ignoreDefinedTags");
    },
    enumerable: true,
});

/**
 * (Optional) A PEM formatted RSA private key for the user. A privateKey or a privateKeyPath must be provided if auth is
 * set to 'ApiKey', ignored otherwise.
 */
export declare const privateKey: string | undefined;
Object.defineProperty(exports, "privateKey", {
    get() {
        return __config.get("privateKey");
    },
    enumerable: true,
});

/**
 * (Optional) The password used to secure the private key.
 */
export declare const privateKeyPassword: string | undefined;
Object.defineProperty(exports, "privateKeyPassword", {
    get() {
        return __config.get("privateKeyPassword");
    },
    enumerable: true,
});

/**
 * (Optional) The path to the user's PEM formatted private key. A privateKey or a privateKeyPath must be provided if auth
 * is set to 'ApiKey', ignored otherwise.
 */
export declare const privateKeyPath: string | undefined;
Object.defineProperty(exports, "privateKeyPath", {
    get() {
        return __config.get("privateKeyPath");
    },
    enumerable: true,
});

/**
 * (Optional) flags to enable realm specific service endpoint.
 */
export declare const realmSpecificServiceEndpointTemplateEnabled: boolean | undefined;
Object.defineProperty(exports, "realmSpecificServiceEndpointTemplateEnabled", {
    get() {
        return __config.getObject<boolean>("realmSpecificServiceEndpointTemplateEnabled");
    },
    enumerable: true,
});

/**
 * (Required) The region for API connections (e.g. us-ashburn-1).
 */
export declare const region: string | undefined;
Object.defineProperty(exports, "region", {
    get() {
        return __config.get("region");
    },
    enumerable: true,
});

/**
 * (Optional) The minimum duration (in seconds) to retry a resource operation in response to an error. The actual retry
 * duration may be longer due to jittering of retry operations. This value is ignored if the `disableAutoRetries` field is
 * set to true.
 */
export declare const retryDurationSeconds: number | undefined;
Object.defineProperty(exports, "retryDurationSeconds", {
    get() {
        return __config.getObject<number>("retryDurationSeconds");
    },
    enumerable: true,
});

/**
 * (Optional) The tenancy OCID for a user. The tenancy OCID can be found at the bottom of user settings in the Oracle Cloud
 * Infrastructure console. Required if auth is set to 'ApiKey', ignored otherwise.
 */
export declare const tenancyOcid: string | undefined;
Object.defineProperty(exports, "tenancyOcid", {
    get() {
        return __config.get("tenancyOcid");
    },
    enumerable: true,
});

export declare const testTimeMaintenanceRebootDue: string | undefined;
Object.defineProperty(exports, "testTimeMaintenanceRebootDue", {
    get() {
        return __config.get("testTimeMaintenanceRebootDue");
    },
    enumerable: true,
});

/**
 * (Optional) The user OCID. This can be found in user settings in the Oracle Cloud Infrastructure console. Required if
 * auth is set to 'ApiKey', ignored otherwise.
 */
export declare const userOcid: string | undefined;
Object.defineProperty(exports, "userOcid", {
    get() {
        return __config.get("userOcid");
    },
    enumerable: true,
});

