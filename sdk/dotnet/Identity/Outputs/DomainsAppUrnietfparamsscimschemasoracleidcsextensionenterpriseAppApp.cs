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
    public sealed class DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppApp
    {
        /// <summary>
        /// (Updatable) Allow Authz policy decision expiry time in seconds.
        /// 
        /// **Added In:** 19.2.1
        /// 
        /// **SCIM++ Properties:**
        /// * idcsMaxValue: 3600
        /// * idcsMinValue: 0
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: integer
        /// * uniqueness: none
        /// </summary>
        public readonly int? AllowAuthzDecisionTtl;
        /// <summary>
        /// (Updatable) Allow Authz Policy.
        /// 
        /// **Added In:** 19.2.1
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: complex
        /// </summary>
        public readonly Outputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppAllowAuthzPolicy? AllowAuthzPolicy;
        /// <summary>
        /// (Updatable) A list of AppResources of this App.
        /// 
        /// **Added In:** 19.2.1
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsCompositeKey: [value]
        /// * idcsSearchable: true
        /// * multiValued: true
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: complex
        /// </summary>
        public readonly ImmutableArray<Outputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppAppResource> AppResources;
        /// <summary>
        /// (Updatable) Deny Authz policy decision expiry time in seconds.
        /// 
        /// **Added In:** 19.2.1
        /// 
        /// **SCIM++ Properties:**
        /// * idcsMaxValue: 3600
        /// * idcsMinValue: 0
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: integer
        /// * uniqueness: none
        /// </summary>
        public readonly int? DenyAuthzDecisionTtl;
        /// <summary>
        /// (Updatable) Deny Authz Policy.
        /// 
        /// **Added In:** 19.2.1
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: complex
        /// </summary>
        public readonly Outputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppDenyAuthzPolicy? DenyAuthzPolicy;

        [OutputConstructor]
        private DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppApp(
            int? allowAuthzDecisionTtl,

            Outputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppAllowAuthzPolicy? allowAuthzPolicy,

            ImmutableArray<Outputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppAppResource> appResources,

            int? denyAuthzDecisionTtl,

            Outputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppDenyAuthzPolicy? denyAuthzPolicy)
        {
            AllowAuthzDecisionTtl = allowAuthzDecisionTtl;
            AllowAuthzPolicy = allowAuthzPolicy;
            AppResources = appResources;
            DenyAuthzDecisionTtl = denyAuthzDecisionTtl;
            DenyAuthzPolicy = denyAuthzPolicy;
        }
    }
}
