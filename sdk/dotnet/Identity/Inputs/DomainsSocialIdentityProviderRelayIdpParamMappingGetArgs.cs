// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsSocialIdentityProviderRelayIdpParamMappingGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Key or name of the relayParam.
        /// 
        /// **Added In:** 2305190132
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
        [Input("relayParamKey", required: true)]
        public Input<string> RelayParamKey { get; set; } = null!;

        /// <summary>
        /// (Updatable) Value of the relayParam (if defined)
        /// 
        /// **Added In:** 2305190132
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("relayParamValue")]
        public Input<string>? RelayParamValue { get; set; }

        public DomainsSocialIdentityProviderRelayIdpParamMappingGetArgs()
        {
        }
        public static new DomainsSocialIdentityProviderRelayIdpParamMappingGetArgs Empty => new DomainsSocialIdentityProviderRelayIdpParamMappingGetArgs();
    }
}
