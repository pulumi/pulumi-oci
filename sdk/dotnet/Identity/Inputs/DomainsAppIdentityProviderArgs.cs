// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsAppIdentityProviderArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Display-name of the IdentityProvider.
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
        /// (Updatable) URI of the IdentityProvider.
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
        /// (Updatable) ID of the IdentityProvider.
        /// 
        /// **SCIM++ Properties:**
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

        public DomainsAppIdentityProviderArgs()
        {
        }
        public static new DomainsAppIdentityProviderArgs Empty => new DomainsAppIdentityProviderArgs();
    }
}
