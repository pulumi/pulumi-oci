// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class DomainsGrantEntitlement
    {
        /// <summary>
        /// The name of the attribute whose value (specified by attributeValue) confers privilege within the service-instance (specified by app).
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: immutable
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string AttributeName;
        /// <summary>
        /// The value of the attribute (specified by attributeName) that confers privilege within the service-instance (specified by app).  If attributeName is 'appRoles', then attributeValue is the ID of the AppRole.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsCsvAttributeName: Display Name
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: immutable
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string AttributeValue;

        [OutputConstructor]
        private DomainsGrantEntitlement(
            string attributeName,

            string attributeValue)
        {
            AttributeName = attributeName;
            AttributeValue = attributeValue;
        }
    }
}