// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsPasswordPolicyConfiguredPasswordPolicyRuleArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The specific password policy rule
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: true
        /// * returned: always
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("key", required: true)]
        public Input<string> Key { get; set; } = null!;

        /// <summary>
        /// (Updatable) User-friendly text that describes a specific password policy rule
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: true
        /// * returned: always
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("value", required: true)]
        public Input<string> Value { get; set; } = null!;

        public DomainsPasswordPolicyConfiguredPasswordPolicyRuleArgs()
        {
        }
        public static new DomainsPasswordPolicyConfiguredPasswordPolicyRuleArgs Empty => new DomainsPasswordPolicyConfiguredPasswordPolicyRuleArgs();
    }
}
