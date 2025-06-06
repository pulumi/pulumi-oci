// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Boolean value to prompt user to setup account recovery during login.
        /// 
        /// **Added In:** 19.1.4
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: request
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        [Input("accountRecoveryRequired")]
        public Input<bool>? AccountRecoveryRequired { get; set; }

        [Input("accounts")]
        private InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserAccountGetArgs>? _accounts;

        /// <summary>
        /// (Updatable) Accounts assigned to this User. Each value of this attribute refers to an app-specific identity that is owned by this User. Therefore, this attribute is a convenience that allows one to see on each User the Apps to which that User has access.
        /// 
        /// **SCIM++ Properties:**
        /// * idcsPii: true
        /// * idcsSearchable: true
        /// * multiValued: true
        /// * mutability: readOnly
        /// * required: false
        /// * returned: request
        /// * type: complex
        /// * uniqueness: none
        /// </summary>
        public InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserAccountGetArgs> Accounts
        {
            get => _accounts ?? (_accounts = new InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserAccountGetArgs>());
            set => _accounts = value;
        }

        [Input("appRoles")]
        private InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserAppRoleGetArgs>? _appRoles;

        /// <summary>
        /// (Updatable) A list of all AppRoles to which this User belongs directly, indirectly or implicitly. The User could belong directly because the User is a member of the AppRole, could belong indirectly because the User is a member of a Group that is a member of the AppRole, or could belong implicitly because the AppRole is public.
        /// 
        /// **SCIM++ Properties:**
        /// * idcsCompositeKey: [value]
        /// * multiValued: true
        /// * mutability: readOnly
        /// * required: false
        /// * returned: request
        /// * type: complex
        /// * uniqueness: none
        /// </summary>
        public InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserAppRoleGetArgs> AppRoles
        {
            get => _appRoles ?? (_appRoles = new InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserAppRoleGetArgs>());
            set => _appRoles = value;
        }

        [Input("applicableAuthenticationTargetApps")]
        private InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserApplicableAuthenticationTargetAppGetArgs>? _applicableAuthenticationTargetApps;

        /// <summary>
        /// (Updatable) The app against which the user will authenticate. The value is not persisted but rather calculated. If the user's delegatedAuthenticationTargetApp is set, that value is returned. Otherwise, the app returned by evaluating the user's applicable Delegated Authentication Policy is returned.
        /// 
        /// **Added In:** 18.1.6
        /// 
        /// **SCIM++ Properties:**
        /// * idcsCompositeKey: [value]
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: request
        /// * type: complex
        /// * uniqueness: none
        /// </summary>
        public InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserApplicableAuthenticationTargetAppGetArgs> ApplicableAuthenticationTargetApps
        {
            get => _applicableAuthenticationTargetApps ?? (_applicableAuthenticationTargetApps = new InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserApplicableAuthenticationTargetAppGetArgs>());
            set => _applicableAuthenticationTargetApps = value;
        }

        /// <summary>
        /// (Updatable) A Boolean value indicating whether or not to send email notification after creating the user. This attribute is not used in update/replace operations.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsCsvAttributeNameMappings: [[columnHeaderName:ByPass Notification]]
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: immutable
        /// * idcsRequiresWriteForAccessFlows: true
        /// * required: false
        /// * returned: never
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        [Input("bypassNotification")]
        public Input<bool>? BypassNotification { get; set; }

        /// <summary>
        /// (Updatable) User creation mechanism
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsCsvAttributeNameMappings: [[defaultValue:import]]
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: immutable
        /// * idcsRequiresWriteForAccessFlows: true
        /// * required: false
        /// * returned: request
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("creationMechanism")]
        public Input<string>? CreationMechanism { get; set; }

        /// <summary>
        /// (Updatable) If set, indicates the user's preferred authentication target app. If not set and the user's \"syncedFromApp\" is set and is enabled for delegated authentication, it is used. Otherwise, the user authenticates locally to Oracle Identity Cloud Service.
        /// 
        /// **Added In:** 17.4.6
        /// 
        /// **SCIM++ Properties:**
        /// * idcsCompositeKey: [value]
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: complex
        /// * uniqueness: none
        /// </summary>
        [Input("delegatedAuthenticationTargetApp")]
        public Input<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserDelegatedAuthenticationTargetAppGetArgs>? DelegatedAuthenticationTargetApp { get; set; }

        /// <summary>
        /// (Updatable) A Boolean value indicating whether or not to hide the getting started page
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        [Input("doNotShowGettingStarted")]
        public Input<bool>? DoNotShowGettingStarted { get; set; }

        [Input("grants")]
        private InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserGrantGetArgs>? _grants;

        /// <summary>
        /// (Updatable) Grants to this User. Each value of this attribute refers to a Grant to this User of some App (and optionally of some entitlement). Therefore, this attribute is a convenience that allows one to see on each User all of the Grants to that User.
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: true
        /// * multiValued: true
        /// * mutability: readOnly
        /// * required: false
        /// * returned: request
        /// * type: complex
        /// * uniqueness: none
        /// </summary>
        public InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserGrantGetArgs> Grants
        {
            get => _grants ?? (_grants = new InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserGrantGetArgs>());
            set => _grants = value;
        }

        /// <summary>
        /// (Updatable) Specifies date time when a User's group membership was last modified.
        /// 
        /// **Added In:** 2304270343
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: request
        /// * type: dateTime
        /// * uniqueness: none
        /// </summary>
        [Input("groupMembershipLastModified")]
        public Input<string>? GroupMembershipLastModified { get; set; }

        [Input("idcsAppRolesLimitedToGroups")]
        private InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserIdcsAppRolesLimitedToGroupGetArgs>? _idcsAppRolesLimitedToGroups;

        /// <summary>
        /// (Updatable) Description:
        /// 
        /// **Added In:** 19.2.1
        /// 
        /// **SCIM++ Properties:**
        /// * idcsCompositeKey: [value, idcsAppRoleId]
        /// * idcsSearchable: true
        /// * multiValued: true
        /// * mutability: readOnly
        /// * required: false
        /// * returned: request
        /// * type: complex
        /// </summary>
        public InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserIdcsAppRolesLimitedToGroupGetArgs> IdcsAppRolesLimitedToGroups
        {
            get => _idcsAppRolesLimitedToGroups ?? (_idcsAppRolesLimitedToGroups = new InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserIdcsAppRolesLimitedToGroupGetArgs>());
            set => _idcsAppRolesLimitedToGroups = value;
        }

        /// <summary>
        /// (Updatable) A Boolean value indicating whether or not a user is enrolled for account recovery
        /// 
        /// **Added In:** 19.1.4
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: request
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        [Input("isAccountRecoveryEnrolled")]
        public Input<bool>? IsAccountRecoveryEnrolled { get; set; }

        /// <summary>
        /// (Updatable) A Boolean value indicating whether or not authentication request by this user should be delegated to a remote app. This value should be true only when the User was originally synced from an app which is enabled for delegated authentication
        /// 
        /// **Added In:** 17.4.6
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: immutable
        /// * required: false
        /// * returned: never
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        [Input("isAuthenticationDelegated")]
        public Input<bool>? IsAuthenticationDelegated { get; set; }

        /// <summary>
        /// (Updatable) A Boolean value indicating whether or not the user is federated.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsCsvAttributeName: Federated
        /// * idcsCsvAttributeNameMappings: [[columnHeaderName:Federated]]
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * idcsRequiresWriteForAccessFlows: true
        /// * required: false
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        [Input("isFederatedUser")]
        public Input<bool>? IsFederatedUser { get; set; }

        /// <summary>
        /// (Updatable) A Boolean value indicating whether or not group membership is normalized for this user.
        /// 
        /// **Deprecated Since: 19.3.3**
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: immutable
        /// * required: false
        /// * returned: never
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        [Input("isGroupMembershipNormalized")]
        public Input<bool>? IsGroupMembershipNormalized { get; set; }

        /// <summary>
        /// (Updatable) A Boolean value Indicates whether this User's group membership has been sync'ed from Group.members to UsersGroups.
        /// 
        /// **Added In:** 19.3.3
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: immutable
        /// * required: false
        /// * returned: never
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        [Input("isGroupMembershipSyncedToUsersGroups")]
        public Input<bool>? IsGroupMembershipSyncedToUsersGroups { get; set; }

        /// <summary>
        /// (Updatable) Specifies the EmailTemplate to be used when sending notification to the user this request is for. If specified, it overrides the default EmailTemplate for this event.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: writeOnly
        /// * required: false
        /// * returned: never
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("notificationEmailTemplateId")]
        public Input<string>? NotificationEmailTemplateId { get; set; }

        /// <summary>
        /// (Updatable) User's preferred landing page following login, logout and reset password.
        /// 
        /// **Added In:** 2302092332
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("preferredUiLandingPage")]
        public Input<string>? PreferredUiLandingPage { get; set; }

        /// <summary>
        /// (Updatable) Indicates if User is a Service User
        /// 
        /// **Added In:** 2306131901
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsCsvAttributeName: Service User
        /// * idcsCsvAttributeNameMappings: [[columnHeaderName:Service User]]
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: immutable
        /// * required: false
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        [Input("serviceUser")]
        public Input<bool>? ServiceUser { get; set; }

        /// <summary>
        /// (Updatable) A supplemental status indicating the reason why a user is disabled
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: request
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("status")]
        public Input<string>? Status { get; set; }

        [Input("supportAccounts")]
        private InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserSupportAccountGetArgs>? _supportAccounts;

        /// <summary>
        /// (Updatable) A list of Support Accounts corresponding to user.
        /// 
        /// **Added In:** 2103141444
        /// 
        /// **SCIM++ Properties:**
        /// * idcsCompositeKey: [value]
        /// * idcsSearchable: true
        /// * multiValued: true
        /// * mutability: readOnly
        /// * required: false
        /// * returned: request
        /// * type: complex
        /// * uniqueness: none
        /// </summary>
        public InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserSupportAccountGetArgs> SupportAccounts
        {
            get => _supportAccounts ?? (_supportAccounts = new InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserSupportAccountGetArgs>());
            set => _supportAccounts = value;
        }

        /// <summary>
        /// (Updatable) Managed App or an Identity Source from where the user is synced. If enabled, this Managed App or Identity Source can be used for performing delegated authentication.
        /// 
        /// **Added In:** 18.2.6
        /// 
        /// **SCIM++ Properties:**
        /// * idcsCompositeKey: [value]
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: complex
        /// * uniqueness: none
        /// </summary>
        [Input("syncedFromApp")]
        public Input<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserSyncedFromAppGetArgs>? SyncedFromApp { get; set; }

        /// <summary>
        /// (Updatable) A Boolean value indicating whether to bypass notification and return user token to be used by an external client to control the user flow.
        /// 
        /// **Added In:** 18.4.2
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: immutable
        /// * required: false
        /// * returned: never
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        [Input("userFlowControlledByExternalClient")]
        public Input<bool>? UserFlowControlledByExternalClient { get; set; }

        /// <summary>
        /// (Updatable) Registration provider
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: immutable
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("userProvider")]
        public Input<string>? UserProvider { get; set; }

        [Input("userTokens")]
        private InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserUserTokenGetArgs>? _userTokens;

        /// <summary>
        /// (Updatable) User token returned if userFlowControlledByExternalClient is true
        /// 
        /// **Added In:** 18.4.2
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: complex
        /// * uniqueness: none
        /// </summary>
        public InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserUserTokenGetArgs> UserTokens
        {
            get => _userTokens ?? (_userTokens = new InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserUserTokenGetArgs>());
            set => _userTokens = value;
        }

        public DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserGetArgs()
        {
        }
        public static new DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserGetArgs Empty => new DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserGetArgs();
    }
}
