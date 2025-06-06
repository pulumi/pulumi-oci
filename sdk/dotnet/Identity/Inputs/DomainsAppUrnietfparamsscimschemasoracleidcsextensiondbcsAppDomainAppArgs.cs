// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsAppUrnietfparamsscimschemasoracleidcsextensiondbcsAppDomainAppArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) DB Domain App display name
        /// 
        /// **Added In:** 18.2.2
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: request
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("display")]
        public Input<string>? Display { get; set; }

        /// <summary>
        /// (Updatable) DB Domain App URI
        /// 
        /// **Added In:** 18.2.2
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
        /// (Updatable) DB Domain App identifier
        /// 
        /// **Added In:** 18.2.2
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("value", required: true)]
        public Input<string> Value { get; set; } = null!;

        public DomainsAppUrnietfparamsscimschemasoracleidcsextensiondbcsAppDomainAppArgs()
        {
        }
        public static new DomainsAppUrnietfparamsscimschemasoracleidcsextensiondbcsAppDomainAppArgs Empty => new DomainsAppUrnietfparamsscimschemasoracleidcsextensiondbcsAppDomainAppArgs();
    }
}
