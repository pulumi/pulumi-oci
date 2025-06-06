// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsGrantAppEntitlementCollectionArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Application Entitlement Collection URI
        /// 
        /// **Added In:** 18.2.4
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: reference
        /// * uniqueness: none
        /// </summary>
        [Input("ref")]
        public Input<string>? Ref { get; set; }

        /// <summary>
        /// Application Entitlement Collection identifier
        /// 
        /// **Added In:** 18.2.4
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: immutable
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("value", required: true)]
        public Input<string> Value { get; set; } = null!;

        public DomainsGrantAppEntitlementCollectionArgs()
        {
        }
        public static new DomainsGrantAppEntitlementCollectionArgs Empty => new DomainsGrantAppEntitlementCollectionArgs();
    }
}
