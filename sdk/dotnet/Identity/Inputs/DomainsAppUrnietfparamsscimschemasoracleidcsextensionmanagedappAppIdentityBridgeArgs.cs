// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppIdentityBridgeArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Name of the IdentityBridge associated with the App.
        /// 
        /// **Added In:** 19.1.4
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// (Updatable) The URI of the IdentityBridge associated with the App.
        /// 
        /// **Added In:** 19.1.4
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
        /// (Updatable) The Id of the IdentityBridge associated with the App.
        /// 
        /// **Added In:** 19.1.4
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: always
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("value")]
        public Input<string>? Value { get; set; }

        public DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppIdentityBridgeArgs()
        {
        }
        public static new DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppIdentityBridgeArgs Empty => new DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppIdentityBridgeArgs();
    }
}
