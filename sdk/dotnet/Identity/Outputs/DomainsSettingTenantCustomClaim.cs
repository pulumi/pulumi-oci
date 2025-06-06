// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class DomainsSettingTenantCustomClaim
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
        public readonly bool AllScopes;
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
        public readonly bool Expression;
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
        public readonly string Mode;
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
        public readonly string Name;
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
        public readonly ImmutableArray<string> Scopes;
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
        public readonly string TokenType;
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
        public readonly string Value;

        [OutputConstructor]
        private DomainsSettingTenantCustomClaim(
            bool allScopes,

            bool expression,

            string mode,

            string name,

            ImmutableArray<string> scopes,

            string tokenType,

            string value)
        {
            AllScopes = allScopes;
            Expression = expression;
            Mode = mode;
            Name = name;
            Scopes = scopes;
            TokenType = tokenType;
            Value = value;
        }
    }
}
