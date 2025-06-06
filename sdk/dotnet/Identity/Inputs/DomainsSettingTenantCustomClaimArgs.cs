// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsSettingTenantCustomClaimArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Indicates if the custom claim is associated with all scopes
        /// 
        /// **Added In:** 18.4.2
        /// 
        /// **SCIM++ Properties:**
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        [Input("allScopes", required: true)]
        public Input<bool> AllScopes { get; set; } = null!;

        /// <summary>
        /// (Updatable) Indicates if the custom claim is an expression
        /// 
        /// **Added In:** 18.4.2
        /// 
        /// **SCIM++ Properties:**
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        [Input("expression", required: true)]
        public Input<bool> Expression { get; set; } = null!;

        /// <summary>
        /// (Updatable) Indicates under what scenario the custom claim will be return
        /// 
        /// **Added In:** 18.4.2
        /// 
        /// **SCIM++ Properties:**
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("mode", required: true)]
        public Input<string> Mode { get; set; } = null!;

        /// <summary>
        /// (Updatable) Custom claim name
        /// 
        /// **Added In:** 18.4.2
        /// 
        /// **SCIM++ Properties:**
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: server
        /// </summary>
        [Input("name", required: true)]
        public Input<string> Name { get; set; } = null!;

        [Input("scopes")]
        private InputList<string>? _scopes;

        /// <summary>
        /// (Updatable) Scopes associated with a specific custom claim
        /// 
        /// **Added In:** 18.4.2
        /// 
        /// **SCIM++ Properties:**
        /// * multiValued: true
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public InputList<string> Scopes
        {
            get => _scopes ?? (_scopes = new InputList<string>());
            set => _scopes = value;
        }

        /// <summary>
        /// (Updatable) Indicates what type of token the custom claim will be embedded
        /// 
        /// **Added In:** 18.4.2
        /// 
        /// **SCIM++ Properties:**
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("tokenType", required: true)]
        public Input<string> TokenType { get; set; } = null!;

        /// <summary>
        /// (Updatable) Custom claim value
        /// 
        /// **Added In:** 18.4.2
        /// 
        /// **SCIM++ Properties:**
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("value", required: true)]
        public Input<string> Value { get; set; } = null!;

        public DomainsSettingTenantCustomClaimArgs()
        {
        }
        public static new DomainsSettingTenantCustomClaimArgs Empty => new DomainsSettingTenantCustomClaimArgs();
    }
}
