// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

// Export members:
export * from "./caBundle";
export * from "./certificate";
export * from "./certificateAuthority";
export * from "./getAssociation";
export * from "./getAssociations";
export * from "./getCaBundle";
export * from "./getCaBundles";
export * from "./getCertificate";
export * from "./getCertificateAuthorities";
export * from "./getCertificateAuthority";
export * from "./getCertificateAuthorityVersion";
export * from "./getCertificateAuthorityVersions";
export * from "./getCertificateVersion";
export * from "./getCertificateVersions";
export * from "./getCertificates";

// Import resources to register:
import { CaBundle } from "./caBundle";
import { Certificate } from "./certificate";
import { CertificateAuthority } from "./certificateAuthority";

const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "oci:CertificatesManagement/caBundle:CaBundle":
                return new CaBundle(name, <any>undefined, { urn })
            case "oci:CertificatesManagement/certificate:Certificate":
                return new Certificate(name, <any>undefined, { urn })
            case "oci:CertificatesManagement/certificateAuthority:CertificateAuthority":
                return new CertificateAuthority(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("oci", "CertificatesManagement/caBundle", _module)
pulumi.runtime.registerResourceModule("oci", "CertificatesManagement/certificate", _module)
pulumi.runtime.registerResourceModule("oci", "CertificatesManagement/certificateAuthority", _module)
