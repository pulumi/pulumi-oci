// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Identity.outputs.GetDomainsIdentitySettingIdcsCreatedBy;
import com.pulumi.oci.Identity.outputs.GetDomainsIdentitySettingIdcsLastModifiedBy;
import com.pulumi.oci.Identity.outputs.GetDomainsIdentitySettingMeta;
import com.pulumi.oci.Identity.outputs.GetDomainsIdentitySettingMyProfile;
import com.pulumi.oci.Identity.outputs.GetDomainsIdentitySettingPosixGid;
import com.pulumi.oci.Identity.outputs.GetDomainsIdentitySettingPosixUid;
import com.pulumi.oci.Identity.outputs.GetDomainsIdentitySettingTag;
import com.pulumi.oci.Identity.outputs.GetDomainsIdentitySettingToken;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetDomainsIdentitySettingResult {
    private @Nullable List<String> attributeSets;
    private @Nullable String attributes;
    private @Nullable String authorization;
    /**
     * @return Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
     * 
     */
    private String compartmentOcid;
    /**
     * @return A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
     * 
     */
    private Boolean deleteInProgress;
    /**
     * @return Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
     * 
     */
    private String domainOcid;
    /**
     * @return Indicates whether to show the &#39;user-is-locked&#39; message during authentication if the user is already locked. The default value is false, which tells the system to show a generic &#39;authentication-failure&#39; message. This is the most secure behavior. If the option is set to true, the system shows a more detailed &#39;error-message&#39; that says the user is locked. This is more helpful but is less secure, for example, because the difference in error-messages could be used to determine which usernames exist and which do not.
     * 
     */
    private Boolean emitLockedMessageWhenUserIsLocked;
    /**
     * @return An identifier for the Resource as defined by the Service Consumer. The externalId may simplify identification of the Resource between Service Consumer and Service Provider by allowing the Consumer to refer to the Resource with its own identifier, obviating the need to store a local mapping between the local identifier of the Resource and the identifier used by the Service Provider. Each Resource MAY include a non-empty externalId value. The value of the externalId attribute is always issued by the Service Consumer and can never be specified by the Service Provider. The Service Provider MUST always interpret the externalId as scoped to the Service Consumer&#39;s tenant.
     * 
     */
    private String externalId;
    /**
     * @return Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider&#39;s entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
     * 
     */
    private String id;
    /**
     * @return The User or App who created the Resource
     * 
     */
    private List<GetDomainsIdentitySettingIdcsCreatedBy> idcsCreatedBies;
    private String idcsEndpoint;
    /**
     * @return The User or App who modified the Resource
     * 
     */
    private List<GetDomainsIdentitySettingIdcsLastModifiedBy> idcsLastModifiedBies;
    /**
     * @return The release number when the resource was upgraded.
     * 
     */
    private String idcsLastUpgradedInRelease;
    /**
     * @return Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
     * 
     */
    private List<String> idcsPreventedOperations;
    private String identitySettingId;
    /**
     * @return A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    private List<GetDomainsIdentitySettingMeta> metas;
    /**
     * @return Whether to allow users to update their own profile.
     * 
     */
    private List<GetDomainsIdentitySettingMyProfile> myProfiles;
    /**
     * @return Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     * 
     */
    private String ocid;
    /**
     * @return A list of Posix Gid settings.
     * 
     */
    private List<GetDomainsIdentitySettingPosixGid> posixGids;
    /**
     * @return A list of Posix Uid settings.
     * 
     */
    private List<GetDomainsIdentitySettingPosixUid> posixUids;
    /**
     * @return Indicates whether the primary email is required.
     * 
     */
    private Boolean primaryEmailRequired;
    /**
     * @return Indicates whether to remove non-RFC5322 compliant emails before creating a user.
     * 
     */
    private Boolean removeInvalidEmails;
    private @Nullable String resourceTypeSchemaVersion;
    /**
     * @return **Added In:** 2302092332
     * 
     */
    private Boolean returnInactiveOverLockedMessage;
    /**
     * @return REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \&#34;enterprise\&#34; extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
     * 
     */
    private List<String> schemas;
    /**
     * @return A list of tags on this resource.
     * 
     */
    private List<GetDomainsIdentitySettingTag> tags;
    /**
     * @return Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     * 
     */
    private String tenancyOcid;
    /**
     * @return A list of tokens and their expiry length.
     * 
     */
    private List<GetDomainsIdentitySettingToken> tokens;
    /**
     * @return Indicates whether a user is allowed to change their own recovery email.
     * 
     */
    private Boolean userAllowedToSetRecoveryEmail;

    private GetDomainsIdentitySettingResult() {}
    public List<String> attributeSets() {
        return this.attributeSets == null ? List.of() : this.attributeSets;
    }
    public Optional<String> attributes() {
        return Optional.ofNullable(this.attributes);
    }
    public Optional<String> authorization() {
        return Optional.ofNullable(this.authorization);
    }
    /**
     * @return Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
     * 
     */
    public String compartmentOcid() {
        return this.compartmentOcid;
    }
    /**
     * @return A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
     * 
     */
    public Boolean deleteInProgress() {
        return this.deleteInProgress;
    }
    /**
     * @return Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
     * 
     */
    public String domainOcid() {
        return this.domainOcid;
    }
    /**
     * @return Indicates whether to show the &#39;user-is-locked&#39; message during authentication if the user is already locked. The default value is false, which tells the system to show a generic &#39;authentication-failure&#39; message. This is the most secure behavior. If the option is set to true, the system shows a more detailed &#39;error-message&#39; that says the user is locked. This is more helpful but is less secure, for example, because the difference in error-messages could be used to determine which usernames exist and which do not.
     * 
     */
    public Boolean emitLockedMessageWhenUserIsLocked() {
        return this.emitLockedMessageWhenUserIsLocked;
    }
    /**
     * @return An identifier for the Resource as defined by the Service Consumer. The externalId may simplify identification of the Resource between Service Consumer and Service Provider by allowing the Consumer to refer to the Resource with its own identifier, obviating the need to store a local mapping between the local identifier of the Resource and the identifier used by the Service Provider. Each Resource MAY include a non-empty externalId value. The value of the externalId attribute is always issued by the Service Consumer and can never be specified by the Service Provider. The Service Provider MUST always interpret the externalId as scoped to the Service Consumer&#39;s tenant.
     * 
     */
    public String externalId() {
        return this.externalId;
    }
    /**
     * @return Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider&#39;s entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The User or App who created the Resource
     * 
     */
    public List<GetDomainsIdentitySettingIdcsCreatedBy> idcsCreatedBies() {
        return this.idcsCreatedBies;
    }
    public String idcsEndpoint() {
        return this.idcsEndpoint;
    }
    /**
     * @return The User or App who modified the Resource
     * 
     */
    public List<GetDomainsIdentitySettingIdcsLastModifiedBy> idcsLastModifiedBies() {
        return this.idcsLastModifiedBies;
    }
    /**
     * @return The release number when the resource was upgraded.
     * 
     */
    public String idcsLastUpgradedInRelease() {
        return this.idcsLastUpgradedInRelease;
    }
    /**
     * @return Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
     * 
     */
    public List<String> idcsPreventedOperations() {
        return this.idcsPreventedOperations;
    }
    public String identitySettingId() {
        return this.identitySettingId;
    }
    /**
     * @return A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    public List<GetDomainsIdentitySettingMeta> metas() {
        return this.metas;
    }
    /**
     * @return Whether to allow users to update their own profile.
     * 
     */
    public List<GetDomainsIdentitySettingMyProfile> myProfiles() {
        return this.myProfiles;
    }
    /**
     * @return Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     * 
     */
    public String ocid() {
        return this.ocid;
    }
    /**
     * @return A list of Posix Gid settings.
     * 
     */
    public List<GetDomainsIdentitySettingPosixGid> posixGids() {
        return this.posixGids;
    }
    /**
     * @return A list of Posix Uid settings.
     * 
     */
    public List<GetDomainsIdentitySettingPosixUid> posixUids() {
        return this.posixUids;
    }
    /**
     * @return Indicates whether the primary email is required.
     * 
     */
    public Boolean primaryEmailRequired() {
        return this.primaryEmailRequired;
    }
    /**
     * @return Indicates whether to remove non-RFC5322 compliant emails before creating a user.
     * 
     */
    public Boolean removeInvalidEmails() {
        return this.removeInvalidEmails;
    }
    public Optional<String> resourceTypeSchemaVersion() {
        return Optional.ofNullable(this.resourceTypeSchemaVersion);
    }
    /**
     * @return **Added In:** 2302092332
     * 
     */
    public Boolean returnInactiveOverLockedMessage() {
        return this.returnInactiveOverLockedMessage;
    }
    /**
     * @return REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \&#34;enterprise\&#34; extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
     * 
     */
    public List<String> schemas() {
        return this.schemas;
    }
    /**
     * @return A list of tags on this resource.
     * 
     */
    public List<GetDomainsIdentitySettingTag> tags() {
        return this.tags;
    }
    /**
     * @return Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     * 
     */
    public String tenancyOcid() {
        return this.tenancyOcid;
    }
    /**
     * @return A list of tokens and their expiry length.
     * 
     */
    public List<GetDomainsIdentitySettingToken> tokens() {
        return this.tokens;
    }
    /**
     * @return Indicates whether a user is allowed to change their own recovery email.
     * 
     */
    public Boolean userAllowedToSetRecoveryEmail() {
        return this.userAllowedToSetRecoveryEmail;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsIdentitySettingResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<String> attributeSets;
        private @Nullable String attributes;
        private @Nullable String authorization;
        private String compartmentOcid;
        private Boolean deleteInProgress;
        private String domainOcid;
        private Boolean emitLockedMessageWhenUserIsLocked;
        private String externalId;
        private String id;
        private List<GetDomainsIdentitySettingIdcsCreatedBy> idcsCreatedBies;
        private String idcsEndpoint;
        private List<GetDomainsIdentitySettingIdcsLastModifiedBy> idcsLastModifiedBies;
        private String idcsLastUpgradedInRelease;
        private List<String> idcsPreventedOperations;
        private String identitySettingId;
        private List<GetDomainsIdentitySettingMeta> metas;
        private List<GetDomainsIdentitySettingMyProfile> myProfiles;
        private String ocid;
        private List<GetDomainsIdentitySettingPosixGid> posixGids;
        private List<GetDomainsIdentitySettingPosixUid> posixUids;
        private Boolean primaryEmailRequired;
        private Boolean removeInvalidEmails;
        private @Nullable String resourceTypeSchemaVersion;
        private Boolean returnInactiveOverLockedMessage;
        private List<String> schemas;
        private List<GetDomainsIdentitySettingTag> tags;
        private String tenancyOcid;
        private List<GetDomainsIdentitySettingToken> tokens;
        private Boolean userAllowedToSetRecoveryEmail;
        public Builder() {}
        public Builder(GetDomainsIdentitySettingResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.attributeSets = defaults.attributeSets;
    	      this.attributes = defaults.attributes;
    	      this.authorization = defaults.authorization;
    	      this.compartmentOcid = defaults.compartmentOcid;
    	      this.deleteInProgress = defaults.deleteInProgress;
    	      this.domainOcid = defaults.domainOcid;
    	      this.emitLockedMessageWhenUserIsLocked = defaults.emitLockedMessageWhenUserIsLocked;
    	      this.externalId = defaults.externalId;
    	      this.id = defaults.id;
    	      this.idcsCreatedBies = defaults.idcsCreatedBies;
    	      this.idcsEndpoint = defaults.idcsEndpoint;
    	      this.idcsLastModifiedBies = defaults.idcsLastModifiedBies;
    	      this.idcsLastUpgradedInRelease = defaults.idcsLastUpgradedInRelease;
    	      this.idcsPreventedOperations = defaults.idcsPreventedOperations;
    	      this.identitySettingId = defaults.identitySettingId;
    	      this.metas = defaults.metas;
    	      this.myProfiles = defaults.myProfiles;
    	      this.ocid = defaults.ocid;
    	      this.posixGids = defaults.posixGids;
    	      this.posixUids = defaults.posixUids;
    	      this.primaryEmailRequired = defaults.primaryEmailRequired;
    	      this.removeInvalidEmails = defaults.removeInvalidEmails;
    	      this.resourceTypeSchemaVersion = defaults.resourceTypeSchemaVersion;
    	      this.returnInactiveOverLockedMessage = defaults.returnInactiveOverLockedMessage;
    	      this.schemas = defaults.schemas;
    	      this.tags = defaults.tags;
    	      this.tenancyOcid = defaults.tenancyOcid;
    	      this.tokens = defaults.tokens;
    	      this.userAllowedToSetRecoveryEmail = defaults.userAllowedToSetRecoveryEmail;
        }

        @CustomType.Setter
        public Builder attributeSets(@Nullable List<String> attributeSets) {

            this.attributeSets = attributeSets;
            return this;
        }
        public Builder attributeSets(String... attributeSets) {
            return attributeSets(List.of(attributeSets));
        }
        @CustomType.Setter
        public Builder attributes(@Nullable String attributes) {

            this.attributes = attributes;
            return this;
        }
        @CustomType.Setter
        public Builder authorization(@Nullable String authorization) {

            this.authorization = authorization;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentOcid(String compartmentOcid) {
            if (compartmentOcid == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingResult", "compartmentOcid");
            }
            this.compartmentOcid = compartmentOcid;
            return this;
        }
        @CustomType.Setter
        public Builder deleteInProgress(Boolean deleteInProgress) {
            if (deleteInProgress == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingResult", "deleteInProgress");
            }
            this.deleteInProgress = deleteInProgress;
            return this;
        }
        @CustomType.Setter
        public Builder domainOcid(String domainOcid) {
            if (domainOcid == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingResult", "domainOcid");
            }
            this.domainOcid = domainOcid;
            return this;
        }
        @CustomType.Setter
        public Builder emitLockedMessageWhenUserIsLocked(Boolean emitLockedMessageWhenUserIsLocked) {
            if (emitLockedMessageWhenUserIsLocked == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingResult", "emitLockedMessageWhenUserIsLocked");
            }
            this.emitLockedMessageWhenUserIsLocked = emitLockedMessageWhenUserIsLocked;
            return this;
        }
        @CustomType.Setter
        public Builder externalId(String externalId) {
            if (externalId == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingResult", "externalId");
            }
            this.externalId = externalId;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder idcsCreatedBies(List<GetDomainsIdentitySettingIdcsCreatedBy> idcsCreatedBies) {
            if (idcsCreatedBies == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingResult", "idcsCreatedBies");
            }
            this.idcsCreatedBies = idcsCreatedBies;
            return this;
        }
        public Builder idcsCreatedBies(GetDomainsIdentitySettingIdcsCreatedBy... idcsCreatedBies) {
            return idcsCreatedBies(List.of(idcsCreatedBies));
        }
        @CustomType.Setter
        public Builder idcsEndpoint(String idcsEndpoint) {
            if (idcsEndpoint == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingResult", "idcsEndpoint");
            }
            this.idcsEndpoint = idcsEndpoint;
            return this;
        }
        @CustomType.Setter
        public Builder idcsLastModifiedBies(List<GetDomainsIdentitySettingIdcsLastModifiedBy> idcsLastModifiedBies) {
            if (idcsLastModifiedBies == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingResult", "idcsLastModifiedBies");
            }
            this.idcsLastModifiedBies = idcsLastModifiedBies;
            return this;
        }
        public Builder idcsLastModifiedBies(GetDomainsIdentitySettingIdcsLastModifiedBy... idcsLastModifiedBies) {
            return idcsLastModifiedBies(List.of(idcsLastModifiedBies));
        }
        @CustomType.Setter
        public Builder idcsLastUpgradedInRelease(String idcsLastUpgradedInRelease) {
            if (idcsLastUpgradedInRelease == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingResult", "idcsLastUpgradedInRelease");
            }
            this.idcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            return this;
        }
        @CustomType.Setter
        public Builder idcsPreventedOperations(List<String> idcsPreventedOperations) {
            if (idcsPreventedOperations == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingResult", "idcsPreventedOperations");
            }
            this.idcsPreventedOperations = idcsPreventedOperations;
            return this;
        }
        public Builder idcsPreventedOperations(String... idcsPreventedOperations) {
            return idcsPreventedOperations(List.of(idcsPreventedOperations));
        }
        @CustomType.Setter
        public Builder identitySettingId(String identitySettingId) {
            if (identitySettingId == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingResult", "identitySettingId");
            }
            this.identitySettingId = identitySettingId;
            return this;
        }
        @CustomType.Setter
        public Builder metas(List<GetDomainsIdentitySettingMeta> metas) {
            if (metas == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingResult", "metas");
            }
            this.metas = metas;
            return this;
        }
        public Builder metas(GetDomainsIdentitySettingMeta... metas) {
            return metas(List.of(metas));
        }
        @CustomType.Setter
        public Builder myProfiles(List<GetDomainsIdentitySettingMyProfile> myProfiles) {
            if (myProfiles == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingResult", "myProfiles");
            }
            this.myProfiles = myProfiles;
            return this;
        }
        public Builder myProfiles(GetDomainsIdentitySettingMyProfile... myProfiles) {
            return myProfiles(List.of(myProfiles));
        }
        @CustomType.Setter
        public Builder ocid(String ocid) {
            if (ocid == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingResult", "ocid");
            }
            this.ocid = ocid;
            return this;
        }
        @CustomType.Setter
        public Builder posixGids(List<GetDomainsIdentitySettingPosixGid> posixGids) {
            if (posixGids == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingResult", "posixGids");
            }
            this.posixGids = posixGids;
            return this;
        }
        public Builder posixGids(GetDomainsIdentitySettingPosixGid... posixGids) {
            return posixGids(List.of(posixGids));
        }
        @CustomType.Setter
        public Builder posixUids(List<GetDomainsIdentitySettingPosixUid> posixUids) {
            if (posixUids == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingResult", "posixUids");
            }
            this.posixUids = posixUids;
            return this;
        }
        public Builder posixUids(GetDomainsIdentitySettingPosixUid... posixUids) {
            return posixUids(List.of(posixUids));
        }
        @CustomType.Setter
        public Builder primaryEmailRequired(Boolean primaryEmailRequired) {
            if (primaryEmailRequired == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingResult", "primaryEmailRequired");
            }
            this.primaryEmailRequired = primaryEmailRequired;
            return this;
        }
        @CustomType.Setter
        public Builder removeInvalidEmails(Boolean removeInvalidEmails) {
            if (removeInvalidEmails == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingResult", "removeInvalidEmails");
            }
            this.removeInvalidEmails = removeInvalidEmails;
            return this;
        }
        @CustomType.Setter
        public Builder resourceTypeSchemaVersion(@Nullable String resourceTypeSchemaVersion) {

            this.resourceTypeSchemaVersion = resourceTypeSchemaVersion;
            return this;
        }
        @CustomType.Setter
        public Builder returnInactiveOverLockedMessage(Boolean returnInactiveOverLockedMessage) {
            if (returnInactiveOverLockedMessage == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingResult", "returnInactiveOverLockedMessage");
            }
            this.returnInactiveOverLockedMessage = returnInactiveOverLockedMessage;
            return this;
        }
        @CustomType.Setter
        public Builder schemas(List<String> schemas) {
            if (schemas == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingResult", "schemas");
            }
            this.schemas = schemas;
            return this;
        }
        public Builder schemas(String... schemas) {
            return schemas(List.of(schemas));
        }
        @CustomType.Setter
        public Builder tags(List<GetDomainsIdentitySettingTag> tags) {
            if (tags == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingResult", "tags");
            }
            this.tags = tags;
            return this;
        }
        public Builder tags(GetDomainsIdentitySettingTag... tags) {
            return tags(List.of(tags));
        }
        @CustomType.Setter
        public Builder tenancyOcid(String tenancyOcid) {
            if (tenancyOcid == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingResult", "tenancyOcid");
            }
            this.tenancyOcid = tenancyOcid;
            return this;
        }
        @CustomType.Setter
        public Builder tokens(List<GetDomainsIdentitySettingToken> tokens) {
            if (tokens == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingResult", "tokens");
            }
            this.tokens = tokens;
            return this;
        }
        public Builder tokens(GetDomainsIdentitySettingToken... tokens) {
            return tokens(List.of(tokens));
        }
        @CustomType.Setter
        public Builder userAllowedToSetRecoveryEmail(Boolean userAllowedToSetRecoveryEmail) {
            if (userAllowedToSetRecoveryEmail == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingResult", "userAllowedToSetRecoveryEmail");
            }
            this.userAllowedToSetRecoveryEmail = userAllowedToSetRecoveryEmail;
            return this;
        }
        public GetDomainsIdentitySettingResult build() {
            final var _resultValue = new GetDomainsIdentitySettingResult();
            _resultValue.attributeSets = attributeSets;
            _resultValue.attributes = attributes;
            _resultValue.authorization = authorization;
            _resultValue.compartmentOcid = compartmentOcid;
            _resultValue.deleteInProgress = deleteInProgress;
            _resultValue.domainOcid = domainOcid;
            _resultValue.emitLockedMessageWhenUserIsLocked = emitLockedMessageWhenUserIsLocked;
            _resultValue.externalId = externalId;
            _resultValue.id = id;
            _resultValue.idcsCreatedBies = idcsCreatedBies;
            _resultValue.idcsEndpoint = idcsEndpoint;
            _resultValue.idcsLastModifiedBies = idcsLastModifiedBies;
            _resultValue.idcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            _resultValue.idcsPreventedOperations = idcsPreventedOperations;
            _resultValue.identitySettingId = identitySettingId;
            _resultValue.metas = metas;
            _resultValue.myProfiles = myProfiles;
            _resultValue.ocid = ocid;
            _resultValue.posixGids = posixGids;
            _resultValue.posixUids = posixUids;
            _resultValue.primaryEmailRequired = primaryEmailRequired;
            _resultValue.removeInvalidEmails = removeInvalidEmails;
            _resultValue.resourceTypeSchemaVersion = resourceTypeSchemaVersion;
            _resultValue.returnInactiveOverLockedMessage = returnInactiveOverLockedMessage;
            _resultValue.schemas = schemas;
            _resultValue.tags = tags;
            _resultValue.tenancyOcid = tenancyOcid;
            _resultValue.tokens = tokens;
            _resultValue.userAllowedToSetRecoveryEmail = userAllowedToSetRecoveryEmail;
            return _resultValue;
        }
    }
}
