// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsIdentityProviderCorrelationPolicyGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Policy display name
        /// 
        /// **Added In:** 20.1.3
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("display")]
        public Input<string>? Display { get; set; }

        /// <summary>
        /// (Updatable) Policy URI
        /// 
        /// **Added In:** 20.1.3
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
        /// (Updatable) A label that indicates the type that this references.
        /// 
        /// **Added In:** 20.1.3
        /// 
        /// **SCIM++ Properties:**
        /// * idcsDefaultValue: Policy
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: immutable
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        /// <summary>
        /// (Updatable) Policy identifier
        /// 
        /// **Added In:** 20.1.3
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

        public DomainsIdentityProviderCorrelationPolicyGetArgs()
        {
        }
        public static new DomainsIdentityProviderCorrelationPolicyGetArgs Empty => new DomainsIdentityProviderCorrelationPolicyGetArgs();
    }
}
