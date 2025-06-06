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
    public sealed class GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionsamlServiceProviderAppGroupAssertionAttributeResult
    {
        /// <summary>
        /// Indicates the filter types that are supported for the Group assertion attributes.
        /// </summary>
        public readonly string Condition;
        /// <summary>
        /// Indicates the format of the assertion attribute.
        /// </summary>
        public readonly string Format;
        /// <summary>
        /// Indicates the group name that are supported for the group assertion attributes.
        /// </summary>
        public readonly string GroupName;
        /// <summary>
        /// The attribute represents the name of the attribute that will be used in the Security Assertion Markup Language (SAML) assertion
        /// </summary>
        public readonly string Name;

        [OutputConstructor]
        private GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionsamlServiceProviderAppGroupAssertionAttributeResult(
            string condition,

            string format,

            string groupName,

            string name)
        {
            Condition = condition;
            Format = format;
            GroupName = groupName;
            Name = name;
        }
    }
}
