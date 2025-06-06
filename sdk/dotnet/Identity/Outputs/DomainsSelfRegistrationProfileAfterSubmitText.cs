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
    public sealed class DomainsSelfRegistrationProfileAfterSubmitText
    {
        /// <summary>
        /// (Updatable) If true, specifies that the localized attribute instance value is the default and will be returned if no localized value found for requesting user's preferred locale. One and only one instance should have this attribute set to true.
        /// 
        /// **SCIM++ Properties:**
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        public readonly bool? Default;
        /// <summary>
        /// (Updatable) Type of user's locale e.g. en-CA
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsCanonicalValueSourceFilter: attrName eq "locales" and attrValues.value eq "$(type)"
        /// * idcsCanonicalValueSourceResourceType: AllowedValue
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string Locale;
        /// <summary>
        /// (Updatable) Localized value of after submit text in corresponding locale
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
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
        private DomainsSelfRegistrationProfileAfterSubmitText(
            bool? @default,

            string locale,

            string value)
        {
            Default = @default;
            Locale = locale;
            Value = value;
        }
    }
}
