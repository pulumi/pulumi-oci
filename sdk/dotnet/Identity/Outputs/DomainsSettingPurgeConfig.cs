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
    public sealed class DomainsSettingPurgeConfig
    {
        /// <summary>
        /// (Updatable) Resource Name
        /// 
        /// **Deprecated Since: 19.1.6**
        /// 
        /// **SCIM++ Properties:**
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: string
        /// </summary>
        public readonly string ResourceName;
        /// <summary>
        /// (Updatable) Retention Period
        /// 
        /// **Deprecated Since: 19.1.6**
        /// 
        /// **SCIM++ Properties:**
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: integer
        /// </summary>
        public readonly int RetentionPeriod;

        [OutputConstructor]
        private DomainsSettingPurgeConfig(
            string resourceName,

            int retentionPeriod)
        {
            ResourceName = resourceName;
            RetentionPeriod = retentionPeriod;
        }
    }
}
