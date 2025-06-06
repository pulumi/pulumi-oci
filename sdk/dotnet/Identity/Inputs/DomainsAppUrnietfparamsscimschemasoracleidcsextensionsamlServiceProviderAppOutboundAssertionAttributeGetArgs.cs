// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsAppUrnietfparamsscimschemasoracleidcsextensionsamlServiceProviderAppOutboundAssertionAttributeGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Mapped Attribute Direction
        /// 
        /// **Added In:** 18.2.6
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("direction")]
        public Input<string>? Direction { get; set; }

        /// <summary>
        /// (Updatable) Mapped Attribute URI
        /// 
        /// **Added In:** 18.2.6
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: reference
        /// * uniqueness: none
        /// </summary>
        [Input("ref")]
        public Input<string>? Ref { get; set; }

        /// <summary>
        /// (Updatable) Mapped Attribute identifier
        /// 
        /// **Added In:** 18.2.6
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * mutability: readOnly
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("value", required: true)]
        public Input<string> Value { get; set; } = null!;

        public DomainsAppUrnietfparamsscimschemasoracleidcsextensionsamlServiceProviderAppOutboundAssertionAttributeGetArgs()
        {
        }
        public static new DomainsAppUrnietfparamsscimschemasoracleidcsextensionsamlServiceProviderAppOutboundAssertionAttributeGetArgs Empty => new DomainsAppUrnietfparamsscimschemasoracleidcsextensionsamlServiceProviderAppOutboundAssertionAttributeGetArgs();
    }
}
