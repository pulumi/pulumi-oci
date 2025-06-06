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
    public sealed class DomainsAppUrnietfparamsscimschemasoracleidcsextensionformFillAppTemplateAppTemplate
    {
        /// <summary>
        /// (Updatable) FormFill Application Configuration CLOB which has to be maintained in Form-Fill APP for legacy code to do Form-Fill injection
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
        public readonly string? Configuration;
        /// <summary>
        /// (Updatable) Indicates how FormFill obtains the username and password of the account that FormFill will use to sign into the target App.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string? FormCredMethod;
        /// <summary>
        /// (Updatable) Credential Sharing Group to which this form-fill application belongs.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string? FormCredentialSharingGroupId;
        /// <summary>
        /// (Updatable) A list of application-formURLs that FormFill should match against any formUrl that the user-specifies when signing in to the target service.  Each item in the list also indicates how FormFill should interpret that formUrl.
        /// 
        /// **SCIM++ Properties:**
        /// * idcsCompositeKey: [formUrl]
        /// * multiValued: true
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: complex
        /// * uniqueness: none
        /// </summary>
        public readonly ImmutableArray<Outputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionformFillAppTemplateAppTemplateFormFillUrlMatch> FormFillUrlMatches;
        /// <summary>
        /// (Updatable) Type of the FormFill application like WebApplication, MainFrameApplication, WindowsApplication. Initially, we will support only WebApplication.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string? FormType;
        /// <summary>
        /// (Updatable) If true, indicates that system is allowed to show the password in plain-text for this account after re-authentication.
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        public readonly bool? RevealPasswordOnForm;
        /// <summary>
        /// (Updatable) If true, indicates that each of the Form-Fill-related attributes that can be inherited from the template actually will be inherited from the template. If false, indicates that the AppTemplate disabled inheritance for these Form-Fill-related attributes.
        /// 
        /// **Added In:** 17.4.2
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        public readonly bool? SyncFromTemplate;
        /// <summary>
        /// (Updatable) Indicates the custom expression, which can combine concat and substring operations with literals and with any attribute of the Oracle Identity Cloud Service User
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string? UserNameFormExpression;
        /// <summary>
        /// (Updatable) Format for generating a username.  This value can be Username or Email Address; any other value will be treated as a custom expression.  A custom expression may combine 'concat' and 'substring' operations with literals and with any attribute of the Oracle Identity Cloud Service user.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsPii: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string? UserNameFormTemplate;

        [OutputConstructor]
        private DomainsAppUrnietfparamsscimschemasoracleidcsextensionformFillAppTemplateAppTemplate(
            string? configuration,

            string? formCredMethod,

            string? formCredentialSharingGroupId,

            ImmutableArray<Outputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionformFillAppTemplateAppTemplateFormFillUrlMatch> formFillUrlMatches,

            string? formType,

            bool? revealPasswordOnForm,

            bool? syncFromTemplate,

            string? userNameFormExpression,

            string? userNameFormTemplate)
        {
            Configuration = configuration;
            FormCredMethod = formCredMethod;
            FormCredentialSharingGroupId = formCredentialSharingGroupId;
            FormFillUrlMatches = formFillUrlMatches;
            FormType = formType;
            RevealPasswordOnForm = revealPasswordOnForm;
            SyncFromTemplate = syncFromTemplate;
            UserNameFormExpression = userNameFormExpression;
            UserNameFormTemplate = userNameFormTemplate;
        }
    }
}
