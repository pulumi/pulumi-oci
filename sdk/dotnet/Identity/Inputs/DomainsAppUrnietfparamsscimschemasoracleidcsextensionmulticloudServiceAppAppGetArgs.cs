// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsAppUrnietfparamsscimschemasoracleidcsextensionmulticloudServiceAppAppGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The multicloud platform service URL which the application will invoke for runtime operations such as AWSCredentials api invocation
        /// 
        /// **Added In:** 2301202328
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: immutable
        /// * required: false
        /// * returned: request
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("multicloudPlatformUrl")]
        public Input<string>? MulticloudPlatformUrl { get; set; }

        /// <summary>
        /// (Updatable) Specifies the service type for which the application is configured for multicloud integration. For applicable external service types, app will invoke multicloud service for runtime operations
        /// 
        /// **Added In:** 2301202328
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: immutable
        /// * required: true
        /// * returned: request
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("multicloudServiceType", required: true)]
        public Input<string> MulticloudServiceType { get; set; } = null!;

        public DomainsAppUrnietfparamsscimschemasoracleidcsextensionmulticloudServiceAppAppGetArgs()
        {
        }
        public static new DomainsAppUrnietfparamsscimschemasoracleidcsextensionmulticloudServiceAppAppGetArgs Empty => new DomainsAppUrnietfparamsscimschemasoracleidcsextensionmulticloudServiceAppAppGetArgs();
    }
}