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
    public sealed class DomainsAppAppsNetworkPerimeter
    {
        /// <summary>
        /// (Updatable) URI of the Network Perimeter.
        /// 
        /// **Added In:** 2010242156
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: reference
        /// * uniqueness: none
        /// </summary>
        public readonly string? Ref;
        /// <summary>
        /// (Updatable) List of identifier of Network Perimeters for App
        /// 
        /// **Added In:** 2010242156
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: always
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private DomainsAppAppsNetworkPerimeter(
            string? @ref,

            string value)
        {
            Ref = @ref;
            Value = value;
        }
    }
}
