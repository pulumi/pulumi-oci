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
    public sealed class DomainsAppRadiusPolicy
    {
        public readonly string? _ref;
        /// <summary>
        /// (Updatable) Identifier of the Policy.
        /// 
        /// **Added In:** 2209070044
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
        public readonly string Value;

        [OutputConstructor]
        private DomainsAppRadiusPolicy(
            string? _ref,

            string value)
        {
            this._ref = _ref;
            Value = value;
        }
    }
}
