// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsIdentitySettingTokenGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Indicates the number of minutes after which the token expires automatically.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: integer
        /// * uniqueness: none
        /// </summary>
        [Input("expiresAfter")]
        public Input<int>? ExpiresAfter { get; set; }

        /// <summary>
        /// (Updatable) The token type.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        public DomainsIdentitySettingTokenGetArgs()
        {
        }
        public static new DomainsIdentitySettingTokenGetArgs Empty => new DomainsIdentitySettingTokenGetArgs();
    }
}