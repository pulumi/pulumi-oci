// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Identity.inputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionformFillAppAppFormFillUrlMatchArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DomainsAppUrnietfparamsscimschemasoracleidcsextensionformFillAppAppArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsAppUrnietfparamsscimschemasoracleidcsextensionformFillAppAppArgs Empty = new DomainsAppUrnietfparamsscimschemasoracleidcsextensionformFillAppAppArgs();

    /**
     * (Updatable) FormFill Application Configuration CLOB which has to be maintained in Form-Fill APP for legacy code to do Form-Fill injection
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="configuration")
    private @Nullable Output<String> configuration;

    /**
     * @return (Updatable) FormFill Application Configuration CLOB which has to be maintained in Form-Fill APP for legacy code to do Form-Fill injection
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> configuration() {
        return Optional.ofNullable(this.configuration);
    }

    /**
     * (Updatable) Indicates how FormFill obtains the username and password of the account that FormFill will use to sign into the target App.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="formCredMethod")
    private @Nullable Output<String> formCredMethod;

    /**
     * @return (Updatable) Indicates how FormFill obtains the username and password of the account that FormFill will use to sign into the target App.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> formCredMethod() {
        return Optional.ofNullable(this.formCredMethod);
    }

    /**
     * (Updatable) Credential Sharing Group to which this form-fill application belongs.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="formCredentialSharingGroupId")
    private @Nullable Output<String> formCredentialSharingGroupId;

    /**
     * @return (Updatable) Credential Sharing Group to which this form-fill application belongs.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> formCredentialSharingGroupId() {
        return Optional.ofNullable(this.formCredentialSharingGroupId);
    }

    /**
     * (Updatable) A list of application-formURLs that FormFill should match against any formUrl that the user-specifies when signing in to the target service.  Each item in the list also indicates how FormFill should interpret that formUrl.
     * 
     * **SCIM++ Properties:**
     * * idcsCompositeKey: [formUrl]
     * * multiValued: true
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: complex
     * * uniqueness: none
     * 
     */
    @Import(name="formFillUrlMatches")
    private @Nullable Output<List<DomainsAppUrnietfparamsscimschemasoracleidcsextensionformFillAppAppFormFillUrlMatchArgs>> formFillUrlMatches;

    /**
     * @return (Updatable) A list of application-formURLs that FormFill should match against any formUrl that the user-specifies when signing in to the target service.  Each item in the list also indicates how FormFill should interpret that formUrl.
     * 
     * **SCIM++ Properties:**
     * * idcsCompositeKey: [formUrl]
     * * multiValued: true
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: complex
     * * uniqueness: none
     * 
     */
    public Optional<Output<List<DomainsAppUrnietfparamsscimschemasoracleidcsextensionformFillAppAppFormFillUrlMatchArgs>>> formFillUrlMatches() {
        return Optional.ofNullable(this.formFillUrlMatches);
    }

    /**
     * (Updatable) Type of the FormFill application like WebApplication, MainFrameApplication, WindowsApplication. Initially, we will support only WebApplication.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="formType")
    private @Nullable Output<String> formType;

    /**
     * @return (Updatable) Type of the FormFill application like WebApplication, MainFrameApplication, WindowsApplication. Initially, we will support only WebApplication.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> formType() {
        return Optional.ofNullable(this.formType);
    }

    /**
     * (Updatable) If true, indicates that system is allowed to show the password in plain-text for this account after re-authentication.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     * 
     */
    @Import(name="revealPasswordOnForm")
    private @Nullable Output<Boolean> revealPasswordOnForm;

    /**
     * @return (Updatable) If true, indicates that system is allowed to show the password in plain-text for this account after re-authentication.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     * 
     */
    public Optional<Output<Boolean>> revealPasswordOnForm() {
        return Optional.ofNullable(this.revealPasswordOnForm);
    }

    /**
     * (Updatable) If true, indicates that each of the Form-Fill-related attributes that can be inherited from the template actually will be inherited from the template. If false, indicates that the AppTemplate on which this App is based has disabled inheritance for these Form-Fill-related attributes.
     * 
     * **Added In:** 17.4.2
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     * 
     */
    @Import(name="syncFromTemplate")
    private @Nullable Output<Boolean> syncFromTemplate;

    /**
     * @return (Updatable) If true, indicates that each of the Form-Fill-related attributes that can be inherited from the template actually will be inherited from the template. If false, indicates that the AppTemplate on which this App is based has disabled inheritance for these Form-Fill-related attributes.
     * 
     * **Added In:** 17.4.2
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     * 
     */
    public Optional<Output<Boolean>> syncFromTemplate() {
        return Optional.ofNullable(this.syncFromTemplate);
    }

    /**
     * (Updatable) Indicates the custom expression, which can combine concat and substring operations with literals and with any attribute of the Oracle Identity Cloud Service User
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="userNameFormExpression")
    private @Nullable Output<String> userNameFormExpression;

    /**
     * @return (Updatable) Indicates the custom expression, which can combine concat and substring operations with literals and with any attribute of the Oracle Identity Cloud Service User
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> userNameFormExpression() {
        return Optional.ofNullable(this.userNameFormExpression);
    }

    /**
     * (Updatable) Format for generating a username.  This value can be Username or Email Address; any other value will be treated as a custom expression.  A custom expression may combine &#39;concat&#39; and &#39;substring&#39; operations with literals and with any attribute of the Oracle Identity Cloud Service user.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsPii: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="userNameFormTemplate")
    private @Nullable Output<String> userNameFormTemplate;

    /**
     * @return (Updatable) Format for generating a username.  This value can be Username or Email Address; any other value will be treated as a custom expression.  A custom expression may combine &#39;concat&#39; and &#39;substring&#39; operations with literals and with any attribute of the Oracle Identity Cloud Service user.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsPii: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> userNameFormTemplate() {
        return Optional.ofNullable(this.userNameFormTemplate);
    }

    private DomainsAppUrnietfparamsscimschemasoracleidcsextensionformFillAppAppArgs() {}

    private DomainsAppUrnietfparamsscimschemasoracleidcsextensionformFillAppAppArgs(DomainsAppUrnietfparamsscimschemasoracleidcsextensionformFillAppAppArgs $) {
        this.configuration = $.configuration;
        this.formCredMethod = $.formCredMethod;
        this.formCredentialSharingGroupId = $.formCredentialSharingGroupId;
        this.formFillUrlMatches = $.formFillUrlMatches;
        this.formType = $.formType;
        this.revealPasswordOnForm = $.revealPasswordOnForm;
        this.syncFromTemplate = $.syncFromTemplate;
        this.userNameFormExpression = $.userNameFormExpression;
        this.userNameFormTemplate = $.userNameFormTemplate;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsAppUrnietfparamsscimschemasoracleidcsextensionformFillAppAppArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsAppUrnietfparamsscimschemasoracleidcsextensionformFillAppAppArgs $;

        public Builder() {
            $ = new DomainsAppUrnietfparamsscimschemasoracleidcsextensionformFillAppAppArgs();
        }

        public Builder(DomainsAppUrnietfparamsscimschemasoracleidcsextensionformFillAppAppArgs defaults) {
            $ = new DomainsAppUrnietfparamsscimschemasoracleidcsextensionformFillAppAppArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param configuration (Updatable) FormFill Application Configuration CLOB which has to be maintained in Form-Fill APP for legacy code to do Form-Fill injection
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder configuration(@Nullable Output<String> configuration) {
            $.configuration = configuration;
            return this;
        }

        /**
         * @param configuration (Updatable) FormFill Application Configuration CLOB which has to be maintained in Form-Fill APP for legacy code to do Form-Fill injection
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder configuration(String configuration) {
            return configuration(Output.of(configuration));
        }

        /**
         * @param formCredMethod (Updatable) Indicates how FormFill obtains the username and password of the account that FormFill will use to sign into the target App.
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder formCredMethod(@Nullable Output<String> formCredMethod) {
            $.formCredMethod = formCredMethod;
            return this;
        }

        /**
         * @param formCredMethod (Updatable) Indicates how FormFill obtains the username and password of the account that FormFill will use to sign into the target App.
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder formCredMethod(String formCredMethod) {
            return formCredMethod(Output.of(formCredMethod));
        }

        /**
         * @param formCredentialSharingGroupId (Updatable) Credential Sharing Group to which this form-fill application belongs.
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder formCredentialSharingGroupId(@Nullable Output<String> formCredentialSharingGroupId) {
            $.formCredentialSharingGroupId = formCredentialSharingGroupId;
            return this;
        }

        /**
         * @param formCredentialSharingGroupId (Updatable) Credential Sharing Group to which this form-fill application belongs.
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder formCredentialSharingGroupId(String formCredentialSharingGroupId) {
            return formCredentialSharingGroupId(Output.of(formCredentialSharingGroupId));
        }

        /**
         * @param formFillUrlMatches (Updatable) A list of application-formURLs that FormFill should match against any formUrl that the user-specifies when signing in to the target service.  Each item in the list also indicates how FormFill should interpret that formUrl.
         * 
         * **SCIM++ Properties:**
         * * idcsCompositeKey: [formUrl]
         * * multiValued: true
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: complex
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder formFillUrlMatches(@Nullable Output<List<DomainsAppUrnietfparamsscimschemasoracleidcsextensionformFillAppAppFormFillUrlMatchArgs>> formFillUrlMatches) {
            $.formFillUrlMatches = formFillUrlMatches;
            return this;
        }

        /**
         * @param formFillUrlMatches (Updatable) A list of application-formURLs that FormFill should match against any formUrl that the user-specifies when signing in to the target service.  Each item in the list also indicates how FormFill should interpret that formUrl.
         * 
         * **SCIM++ Properties:**
         * * idcsCompositeKey: [formUrl]
         * * multiValued: true
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: complex
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder formFillUrlMatches(List<DomainsAppUrnietfparamsscimschemasoracleidcsextensionformFillAppAppFormFillUrlMatchArgs> formFillUrlMatches) {
            return formFillUrlMatches(Output.of(formFillUrlMatches));
        }

        /**
         * @param formFillUrlMatches (Updatable) A list of application-formURLs that FormFill should match against any formUrl that the user-specifies when signing in to the target service.  Each item in the list also indicates how FormFill should interpret that formUrl.
         * 
         * **SCIM++ Properties:**
         * * idcsCompositeKey: [formUrl]
         * * multiValued: true
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: complex
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder formFillUrlMatches(DomainsAppUrnietfparamsscimschemasoracleidcsextensionformFillAppAppFormFillUrlMatchArgs... formFillUrlMatches) {
            return formFillUrlMatches(List.of(formFillUrlMatches));
        }

        /**
         * @param formType (Updatable) Type of the FormFill application like WebApplication, MainFrameApplication, WindowsApplication. Initially, we will support only WebApplication.
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder formType(@Nullable Output<String> formType) {
            $.formType = formType;
            return this;
        }

        /**
         * @param formType (Updatable) Type of the FormFill application like WebApplication, MainFrameApplication, WindowsApplication. Initially, we will support only WebApplication.
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder formType(String formType) {
            return formType(Output.of(formType));
        }

        /**
         * @param revealPasswordOnForm (Updatable) If true, indicates that system is allowed to show the password in plain-text for this account after re-authentication.
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: boolean
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder revealPasswordOnForm(@Nullable Output<Boolean> revealPasswordOnForm) {
            $.revealPasswordOnForm = revealPasswordOnForm;
            return this;
        }

        /**
         * @param revealPasswordOnForm (Updatable) If true, indicates that system is allowed to show the password in plain-text for this account after re-authentication.
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: boolean
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder revealPasswordOnForm(Boolean revealPasswordOnForm) {
            return revealPasswordOnForm(Output.of(revealPasswordOnForm));
        }

        /**
         * @param syncFromTemplate (Updatable) If true, indicates that each of the Form-Fill-related attributes that can be inherited from the template actually will be inherited from the template. If false, indicates that the AppTemplate on which this App is based has disabled inheritance for these Form-Fill-related attributes.
         * 
         * **Added In:** 17.4.2
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: default
         * * type: boolean
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder syncFromTemplate(@Nullable Output<Boolean> syncFromTemplate) {
            $.syncFromTemplate = syncFromTemplate;
            return this;
        }

        /**
         * @param syncFromTemplate (Updatable) If true, indicates that each of the Form-Fill-related attributes that can be inherited from the template actually will be inherited from the template. If false, indicates that the AppTemplate on which this App is based has disabled inheritance for these Form-Fill-related attributes.
         * 
         * **Added In:** 17.4.2
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: default
         * * type: boolean
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder syncFromTemplate(Boolean syncFromTemplate) {
            return syncFromTemplate(Output.of(syncFromTemplate));
        }

        /**
         * @param userNameFormExpression (Updatable) Indicates the custom expression, which can combine concat and substring operations with literals and with any attribute of the Oracle Identity Cloud Service User
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder userNameFormExpression(@Nullable Output<String> userNameFormExpression) {
            $.userNameFormExpression = userNameFormExpression;
            return this;
        }

        /**
         * @param userNameFormExpression (Updatable) Indicates the custom expression, which can combine concat and substring operations with literals and with any attribute of the Oracle Identity Cloud Service User
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder userNameFormExpression(String userNameFormExpression) {
            return userNameFormExpression(Output.of(userNameFormExpression));
        }

        /**
         * @param userNameFormTemplate (Updatable) Format for generating a username.  This value can be Username or Email Address; any other value will be treated as a custom expression.  A custom expression may combine &#39;concat&#39; and &#39;substring&#39; operations with literals and with any attribute of the Oracle Identity Cloud Service user.
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsPii: true
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder userNameFormTemplate(@Nullable Output<String> userNameFormTemplate) {
            $.userNameFormTemplate = userNameFormTemplate;
            return this;
        }

        /**
         * @param userNameFormTemplate (Updatable) Format for generating a username.  This value can be Username or Email Address; any other value will be treated as a custom expression.  A custom expression may combine &#39;concat&#39; and &#39;substring&#39; operations with literals and with any attribute of the Oracle Identity Cloud Service user.
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsPii: true
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder userNameFormTemplate(String userNameFormTemplate) {
            return userNameFormTemplate(Output.of(userNameFormTemplate));
        }

        public DomainsAppUrnietfparamsscimschemasoracleidcsextensionformFillAppAppArgs build() {
            return $;
        }
    }

}
