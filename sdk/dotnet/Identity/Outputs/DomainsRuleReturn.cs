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
    public sealed class DomainsRuleReturn
    {
        /// <summary>
        /// (Updatable) Attribute name of an individual value to be returned.
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// (Updatable) The Groovy script that is run to generate output for the rule, if the policy type allows the return value to be a Groovy script.
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
        public readonly string? ReturnGroovy;
        /// <summary>
        /// (Updatable) Attribute value of some attribute to be returned.
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private DomainsRuleReturn(
            string name,

            string? returnGroovy,

            string value)
        {
            Name = name;
            ReturnGroovy = returnGroovy;
            Value = value;
        }
    }
}
