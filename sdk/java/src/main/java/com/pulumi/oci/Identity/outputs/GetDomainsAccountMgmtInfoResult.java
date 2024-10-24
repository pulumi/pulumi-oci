// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Identity.outputs.GetDomainsAccountMgmtInfoApp;
import com.pulumi.oci.Identity.outputs.GetDomainsAccountMgmtInfoIdcsCreatedBy;
import com.pulumi.oci.Identity.outputs.GetDomainsAccountMgmtInfoIdcsLastModifiedBy;
import com.pulumi.oci.Identity.outputs.GetDomainsAccountMgmtInfoMatchingOwner;
import com.pulumi.oci.Identity.outputs.GetDomainsAccountMgmtInfoMeta;
import com.pulumi.oci.Identity.outputs.GetDomainsAccountMgmtInfoObjectClass;
import com.pulumi.oci.Identity.outputs.GetDomainsAccountMgmtInfoOwner;
import com.pulumi.oci.Identity.outputs.GetDomainsAccountMgmtInfoResourceType;
import com.pulumi.oci.Identity.outputs.GetDomainsAccountMgmtInfoTag;
import com.pulumi.oci.Identity.outputs.GetDomainsAccountMgmtInfoUserWalletArtifact;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetDomainsAccountMgmtInfoResult {
    private String accountMgmtInfoId;
    /**
     * @return Type of Account
     * 
     */
    private String accountType;
    /**
     * @return If true, this App is able to participate in runtime services, such as automatic-login, OAuth, and SAML. If false, all runtime services are disabled for this App and only administrative operations can be performed.
     * 
     */
    private Boolean active;
    /**
     * @return Application on which the account is based
     * 
     */
    private List<GetDomainsAccountMgmtInfoApp> apps;
    private @Nullable List<String> attributeSets;
    private @Nullable String attributes;
    private @Nullable String authorization;
    /**
     * @return Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
     * 
     */
    private String compartmentOcid;
    /**
     * @return Unique key for this AccountMgmtInfo, which is used to prevent duplicate AccountMgmtInfo resources. Key is composed of a subset of app, owner and accountType.
     * 
     */
    private String compositeKey;
    /**
     * @return A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
     * 
     */
    private Boolean deleteInProgress;
    /**
     * @return If true, a back-fill grant will not be created for a connected managed app as part of account creation.
     * 
     */
    private Boolean doNotBackFillGrants;
    /**
     * @return If true, the operation will not be performed on the target
     * 
     */
    private Boolean doNotPerformActionOnTarget;
    /**
     * @return Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
     * 
     */
    private String domainOcid;
    /**
     * @return If true, this account has been marked as a favorite of the User who owns it
     * 
     */
    private Boolean favorite;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The User or App who created the Resource
     * 
     */
    private List<GetDomainsAccountMgmtInfoIdcsCreatedBy> idcsCreatedBies;
    private String idcsEndpoint;
    /**
     * @return The User or App who modified the Resource
     * 
     */
    private List<GetDomainsAccountMgmtInfoIdcsLastModifiedBy> idcsLastModifiedBies;
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
    /**
     * @return If true, indicates that this managed object is an account, which is an identity that represents a user in the context of a specific application
     * 
     */
    private Boolean isAccount;
    /**
     * @return Last accessed timestamp of an application
     * 
     */
    private String lastAccessed;
    /**
     * @return Matching owning users of the account
     * 
     */
    private List<GetDomainsAccountMgmtInfoMatchingOwner> matchingOwners;
    /**
     * @return A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    private List<GetDomainsAccountMgmtInfoMeta> metas;
    /**
     * @return Name of the Account
     * 
     */
    private String name;
    /**
     * @return Object-class of the Account
     * 
     */
    private List<GetDomainsAccountMgmtInfoObjectClass> objectClasses;
    /**
     * @return Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     * 
     */
    private String ocid;
    /**
     * @return The context in which the operation is performed on the account.
     * 
     */
    private String operationContext;
    /**
     * @return Owning user of the account
     * 
     */
    private List<GetDomainsAccountMgmtInfoOwner> owners;
    /**
     * @return If true, then the response to the account creation operation on a connected managed app returns a preview of the account data that is evaluated by the attribute value generation policy. Note that an account will not be created on the target application when this attribute is set to true.
     * 
     */
    private Boolean previewOnly;
    private @Nullable String resourceTypeSchemaVersion;
    /**
     * @return Resource Type of the Account
     * 
     */
    private List<GetDomainsAccountMgmtInfoResourceType> resourceTypes;
    /**
     * @return REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \&#34;enterprise\&#34; extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
     * 
     */
    private List<String> schemas;
    /**
     * @return Last recorded sync response for the account
     * 
     */
    private String syncResponse;
    /**
     * @return Last recorded sync situation for the account
     * 
     */
    private String syncSituation;
    /**
     * @return Last sync timestamp of the account
     * 
     */
    private String syncTimestamp;
    /**
     * @return A list of tags on this resource.
     * 
     */
    private List<GetDomainsAccountMgmtInfoTag> tags;
    /**
     * @return Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     * 
     */
    private String tenancyOcid;
    /**
     * @return Unique identifier of the Account
     * 
     */
    private String uid;
    /**
     * @return The UserWalletArtifact that contains the credentials that the system will use when performing Secure Form-Fill to log the user in to this application
     * 
     */
    private List<GetDomainsAccountMgmtInfoUserWalletArtifact> userWalletArtifacts;

    private GetDomainsAccountMgmtInfoResult() {}
    public String accountMgmtInfoId() {
        return this.accountMgmtInfoId;
    }
    /**
     * @return Type of Account
     * 
     */
    public String accountType() {
        return this.accountType;
    }
    /**
     * @return If true, this App is able to participate in runtime services, such as automatic-login, OAuth, and SAML. If false, all runtime services are disabled for this App and only administrative operations can be performed.
     * 
     */
    public Boolean active() {
        return this.active;
    }
    /**
     * @return Application on which the account is based
     * 
     */
    public List<GetDomainsAccountMgmtInfoApp> apps() {
        return this.apps;
    }
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
     * @return Unique key for this AccountMgmtInfo, which is used to prevent duplicate AccountMgmtInfo resources. Key is composed of a subset of app, owner and accountType.
     * 
     */
    public String compositeKey() {
        return this.compositeKey;
    }
    /**
     * @return A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
     * 
     */
    public Boolean deleteInProgress() {
        return this.deleteInProgress;
    }
    /**
     * @return If true, a back-fill grant will not be created for a connected managed app as part of account creation.
     * 
     */
    public Boolean doNotBackFillGrants() {
        return this.doNotBackFillGrants;
    }
    /**
     * @return If true, the operation will not be performed on the target
     * 
     */
    public Boolean doNotPerformActionOnTarget() {
        return this.doNotPerformActionOnTarget;
    }
    /**
     * @return Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
     * 
     */
    public String domainOcid() {
        return this.domainOcid;
    }
    /**
     * @return If true, this account has been marked as a favorite of the User who owns it
     * 
     */
    public Boolean favorite() {
        return this.favorite;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The User or App who created the Resource
     * 
     */
    public List<GetDomainsAccountMgmtInfoIdcsCreatedBy> idcsCreatedBies() {
        return this.idcsCreatedBies;
    }
    public String idcsEndpoint() {
        return this.idcsEndpoint;
    }
    /**
     * @return The User or App who modified the Resource
     * 
     */
    public List<GetDomainsAccountMgmtInfoIdcsLastModifiedBy> idcsLastModifiedBies() {
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
    /**
     * @return If true, indicates that this managed object is an account, which is an identity that represents a user in the context of a specific application
     * 
     */
    public Boolean isAccount() {
        return this.isAccount;
    }
    /**
     * @return Last accessed timestamp of an application
     * 
     */
    public String lastAccessed() {
        return this.lastAccessed;
    }
    /**
     * @return Matching owning users of the account
     * 
     */
    public List<GetDomainsAccountMgmtInfoMatchingOwner> matchingOwners() {
        return this.matchingOwners;
    }
    /**
     * @return A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    public List<GetDomainsAccountMgmtInfoMeta> metas() {
        return this.metas;
    }
    /**
     * @return Name of the Account
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Object-class of the Account
     * 
     */
    public List<GetDomainsAccountMgmtInfoObjectClass> objectClasses() {
        return this.objectClasses;
    }
    /**
     * @return Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     * 
     */
    public String ocid() {
        return this.ocid;
    }
    /**
     * @return The context in which the operation is performed on the account.
     * 
     */
    public String operationContext() {
        return this.operationContext;
    }
    /**
     * @return Owning user of the account
     * 
     */
    public List<GetDomainsAccountMgmtInfoOwner> owners() {
        return this.owners;
    }
    /**
     * @return If true, then the response to the account creation operation on a connected managed app returns a preview of the account data that is evaluated by the attribute value generation policy. Note that an account will not be created on the target application when this attribute is set to true.
     * 
     */
    public Boolean previewOnly() {
        return this.previewOnly;
    }
    public Optional<String> resourceTypeSchemaVersion() {
        return Optional.ofNullable(this.resourceTypeSchemaVersion);
    }
    /**
     * @return Resource Type of the Account
     * 
     */
    public List<GetDomainsAccountMgmtInfoResourceType> resourceTypes() {
        return this.resourceTypes;
    }
    /**
     * @return REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \&#34;enterprise\&#34; extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
     * 
     */
    public List<String> schemas() {
        return this.schemas;
    }
    /**
     * @return Last recorded sync response for the account
     * 
     */
    public String syncResponse() {
        return this.syncResponse;
    }
    /**
     * @return Last recorded sync situation for the account
     * 
     */
    public String syncSituation() {
        return this.syncSituation;
    }
    /**
     * @return Last sync timestamp of the account
     * 
     */
    public String syncTimestamp() {
        return this.syncTimestamp;
    }
    /**
     * @return A list of tags on this resource.
     * 
     */
    public List<GetDomainsAccountMgmtInfoTag> tags() {
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
     * @return Unique identifier of the Account
     * 
     */
    public String uid() {
        return this.uid;
    }
    /**
     * @return The UserWalletArtifact that contains the credentials that the system will use when performing Secure Form-Fill to log the user in to this application
     * 
     */
    public List<GetDomainsAccountMgmtInfoUserWalletArtifact> userWalletArtifacts() {
        return this.userWalletArtifacts;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsAccountMgmtInfoResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String accountMgmtInfoId;
        private String accountType;
        private Boolean active;
        private List<GetDomainsAccountMgmtInfoApp> apps;
        private @Nullable List<String> attributeSets;
        private @Nullable String attributes;
        private @Nullable String authorization;
        private String compartmentOcid;
        private String compositeKey;
        private Boolean deleteInProgress;
        private Boolean doNotBackFillGrants;
        private Boolean doNotPerformActionOnTarget;
        private String domainOcid;
        private Boolean favorite;
        private String id;
        private List<GetDomainsAccountMgmtInfoIdcsCreatedBy> idcsCreatedBies;
        private String idcsEndpoint;
        private List<GetDomainsAccountMgmtInfoIdcsLastModifiedBy> idcsLastModifiedBies;
        private String idcsLastUpgradedInRelease;
        private List<String> idcsPreventedOperations;
        private Boolean isAccount;
        private String lastAccessed;
        private List<GetDomainsAccountMgmtInfoMatchingOwner> matchingOwners;
        private List<GetDomainsAccountMgmtInfoMeta> metas;
        private String name;
        private List<GetDomainsAccountMgmtInfoObjectClass> objectClasses;
        private String ocid;
        private String operationContext;
        private List<GetDomainsAccountMgmtInfoOwner> owners;
        private Boolean previewOnly;
        private @Nullable String resourceTypeSchemaVersion;
        private List<GetDomainsAccountMgmtInfoResourceType> resourceTypes;
        private List<String> schemas;
        private String syncResponse;
        private String syncSituation;
        private String syncTimestamp;
        private List<GetDomainsAccountMgmtInfoTag> tags;
        private String tenancyOcid;
        private String uid;
        private List<GetDomainsAccountMgmtInfoUserWalletArtifact> userWalletArtifacts;
        public Builder() {}
        public Builder(GetDomainsAccountMgmtInfoResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.accountMgmtInfoId = defaults.accountMgmtInfoId;
    	      this.accountType = defaults.accountType;
    	      this.active = defaults.active;
    	      this.apps = defaults.apps;
    	      this.attributeSets = defaults.attributeSets;
    	      this.attributes = defaults.attributes;
    	      this.authorization = defaults.authorization;
    	      this.compartmentOcid = defaults.compartmentOcid;
    	      this.compositeKey = defaults.compositeKey;
    	      this.deleteInProgress = defaults.deleteInProgress;
    	      this.doNotBackFillGrants = defaults.doNotBackFillGrants;
    	      this.doNotPerformActionOnTarget = defaults.doNotPerformActionOnTarget;
    	      this.domainOcid = defaults.domainOcid;
    	      this.favorite = defaults.favorite;
    	      this.id = defaults.id;
    	      this.idcsCreatedBies = defaults.idcsCreatedBies;
    	      this.idcsEndpoint = defaults.idcsEndpoint;
    	      this.idcsLastModifiedBies = defaults.idcsLastModifiedBies;
    	      this.idcsLastUpgradedInRelease = defaults.idcsLastUpgradedInRelease;
    	      this.idcsPreventedOperations = defaults.idcsPreventedOperations;
    	      this.isAccount = defaults.isAccount;
    	      this.lastAccessed = defaults.lastAccessed;
    	      this.matchingOwners = defaults.matchingOwners;
    	      this.metas = defaults.metas;
    	      this.name = defaults.name;
    	      this.objectClasses = defaults.objectClasses;
    	      this.ocid = defaults.ocid;
    	      this.operationContext = defaults.operationContext;
    	      this.owners = defaults.owners;
    	      this.previewOnly = defaults.previewOnly;
    	      this.resourceTypeSchemaVersion = defaults.resourceTypeSchemaVersion;
    	      this.resourceTypes = defaults.resourceTypes;
    	      this.schemas = defaults.schemas;
    	      this.syncResponse = defaults.syncResponse;
    	      this.syncSituation = defaults.syncSituation;
    	      this.syncTimestamp = defaults.syncTimestamp;
    	      this.tags = defaults.tags;
    	      this.tenancyOcid = defaults.tenancyOcid;
    	      this.uid = defaults.uid;
    	      this.userWalletArtifacts = defaults.userWalletArtifacts;
        }

        @CustomType.Setter
        public Builder accountMgmtInfoId(String accountMgmtInfoId) {
            if (accountMgmtInfoId == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "accountMgmtInfoId");
            }
            this.accountMgmtInfoId = accountMgmtInfoId;
            return this;
        }
        @CustomType.Setter
        public Builder accountType(String accountType) {
            if (accountType == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "accountType");
            }
            this.accountType = accountType;
            return this;
        }
        @CustomType.Setter
        public Builder active(Boolean active) {
            if (active == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "active");
            }
            this.active = active;
            return this;
        }
        @CustomType.Setter
        public Builder apps(List<GetDomainsAccountMgmtInfoApp> apps) {
            if (apps == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "apps");
            }
            this.apps = apps;
            return this;
        }
        public Builder apps(GetDomainsAccountMgmtInfoApp... apps) {
            return apps(List.of(apps));
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
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "compartmentOcid");
            }
            this.compartmentOcid = compartmentOcid;
            return this;
        }
        @CustomType.Setter
        public Builder compositeKey(String compositeKey) {
            if (compositeKey == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "compositeKey");
            }
            this.compositeKey = compositeKey;
            return this;
        }
        @CustomType.Setter
        public Builder deleteInProgress(Boolean deleteInProgress) {
            if (deleteInProgress == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "deleteInProgress");
            }
            this.deleteInProgress = deleteInProgress;
            return this;
        }
        @CustomType.Setter
        public Builder doNotBackFillGrants(Boolean doNotBackFillGrants) {
            if (doNotBackFillGrants == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "doNotBackFillGrants");
            }
            this.doNotBackFillGrants = doNotBackFillGrants;
            return this;
        }
        @CustomType.Setter
        public Builder doNotPerformActionOnTarget(Boolean doNotPerformActionOnTarget) {
            if (doNotPerformActionOnTarget == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "doNotPerformActionOnTarget");
            }
            this.doNotPerformActionOnTarget = doNotPerformActionOnTarget;
            return this;
        }
        @CustomType.Setter
        public Builder domainOcid(String domainOcid) {
            if (domainOcid == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "domainOcid");
            }
            this.domainOcid = domainOcid;
            return this;
        }
        @CustomType.Setter
        public Builder favorite(Boolean favorite) {
            if (favorite == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "favorite");
            }
            this.favorite = favorite;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder idcsCreatedBies(List<GetDomainsAccountMgmtInfoIdcsCreatedBy> idcsCreatedBies) {
            if (idcsCreatedBies == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "idcsCreatedBies");
            }
            this.idcsCreatedBies = idcsCreatedBies;
            return this;
        }
        public Builder idcsCreatedBies(GetDomainsAccountMgmtInfoIdcsCreatedBy... idcsCreatedBies) {
            return idcsCreatedBies(List.of(idcsCreatedBies));
        }
        @CustomType.Setter
        public Builder idcsEndpoint(String idcsEndpoint) {
            if (idcsEndpoint == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "idcsEndpoint");
            }
            this.idcsEndpoint = idcsEndpoint;
            return this;
        }
        @CustomType.Setter
        public Builder idcsLastModifiedBies(List<GetDomainsAccountMgmtInfoIdcsLastModifiedBy> idcsLastModifiedBies) {
            if (idcsLastModifiedBies == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "idcsLastModifiedBies");
            }
            this.idcsLastModifiedBies = idcsLastModifiedBies;
            return this;
        }
        public Builder idcsLastModifiedBies(GetDomainsAccountMgmtInfoIdcsLastModifiedBy... idcsLastModifiedBies) {
            return idcsLastModifiedBies(List.of(idcsLastModifiedBies));
        }
        @CustomType.Setter
        public Builder idcsLastUpgradedInRelease(String idcsLastUpgradedInRelease) {
            if (idcsLastUpgradedInRelease == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "idcsLastUpgradedInRelease");
            }
            this.idcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            return this;
        }
        @CustomType.Setter
        public Builder idcsPreventedOperations(List<String> idcsPreventedOperations) {
            if (idcsPreventedOperations == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "idcsPreventedOperations");
            }
            this.idcsPreventedOperations = idcsPreventedOperations;
            return this;
        }
        public Builder idcsPreventedOperations(String... idcsPreventedOperations) {
            return idcsPreventedOperations(List.of(idcsPreventedOperations));
        }
        @CustomType.Setter
        public Builder isAccount(Boolean isAccount) {
            if (isAccount == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "isAccount");
            }
            this.isAccount = isAccount;
            return this;
        }
        @CustomType.Setter
        public Builder lastAccessed(String lastAccessed) {
            if (lastAccessed == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "lastAccessed");
            }
            this.lastAccessed = lastAccessed;
            return this;
        }
        @CustomType.Setter
        public Builder matchingOwners(List<GetDomainsAccountMgmtInfoMatchingOwner> matchingOwners) {
            if (matchingOwners == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "matchingOwners");
            }
            this.matchingOwners = matchingOwners;
            return this;
        }
        public Builder matchingOwners(GetDomainsAccountMgmtInfoMatchingOwner... matchingOwners) {
            return matchingOwners(List.of(matchingOwners));
        }
        @CustomType.Setter
        public Builder metas(List<GetDomainsAccountMgmtInfoMeta> metas) {
            if (metas == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "metas");
            }
            this.metas = metas;
            return this;
        }
        public Builder metas(GetDomainsAccountMgmtInfoMeta... metas) {
            return metas(List.of(metas));
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder objectClasses(List<GetDomainsAccountMgmtInfoObjectClass> objectClasses) {
            if (objectClasses == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "objectClasses");
            }
            this.objectClasses = objectClasses;
            return this;
        }
        public Builder objectClasses(GetDomainsAccountMgmtInfoObjectClass... objectClasses) {
            return objectClasses(List.of(objectClasses));
        }
        @CustomType.Setter
        public Builder ocid(String ocid) {
            if (ocid == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "ocid");
            }
            this.ocid = ocid;
            return this;
        }
        @CustomType.Setter
        public Builder operationContext(String operationContext) {
            if (operationContext == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "operationContext");
            }
            this.operationContext = operationContext;
            return this;
        }
        @CustomType.Setter
        public Builder owners(List<GetDomainsAccountMgmtInfoOwner> owners) {
            if (owners == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "owners");
            }
            this.owners = owners;
            return this;
        }
        public Builder owners(GetDomainsAccountMgmtInfoOwner... owners) {
            return owners(List.of(owners));
        }
        @CustomType.Setter
        public Builder previewOnly(Boolean previewOnly) {
            if (previewOnly == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "previewOnly");
            }
            this.previewOnly = previewOnly;
            return this;
        }
        @CustomType.Setter
        public Builder resourceTypeSchemaVersion(@Nullable String resourceTypeSchemaVersion) {

            this.resourceTypeSchemaVersion = resourceTypeSchemaVersion;
            return this;
        }
        @CustomType.Setter
        public Builder resourceTypes(List<GetDomainsAccountMgmtInfoResourceType> resourceTypes) {
            if (resourceTypes == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "resourceTypes");
            }
            this.resourceTypes = resourceTypes;
            return this;
        }
        public Builder resourceTypes(GetDomainsAccountMgmtInfoResourceType... resourceTypes) {
            return resourceTypes(List.of(resourceTypes));
        }
        @CustomType.Setter
        public Builder schemas(List<String> schemas) {
            if (schemas == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "schemas");
            }
            this.schemas = schemas;
            return this;
        }
        public Builder schemas(String... schemas) {
            return schemas(List.of(schemas));
        }
        @CustomType.Setter
        public Builder syncResponse(String syncResponse) {
            if (syncResponse == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "syncResponse");
            }
            this.syncResponse = syncResponse;
            return this;
        }
        @CustomType.Setter
        public Builder syncSituation(String syncSituation) {
            if (syncSituation == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "syncSituation");
            }
            this.syncSituation = syncSituation;
            return this;
        }
        @CustomType.Setter
        public Builder syncTimestamp(String syncTimestamp) {
            if (syncTimestamp == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "syncTimestamp");
            }
            this.syncTimestamp = syncTimestamp;
            return this;
        }
        @CustomType.Setter
        public Builder tags(List<GetDomainsAccountMgmtInfoTag> tags) {
            if (tags == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "tags");
            }
            this.tags = tags;
            return this;
        }
        public Builder tags(GetDomainsAccountMgmtInfoTag... tags) {
            return tags(List.of(tags));
        }
        @CustomType.Setter
        public Builder tenancyOcid(String tenancyOcid) {
            if (tenancyOcid == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "tenancyOcid");
            }
            this.tenancyOcid = tenancyOcid;
            return this;
        }
        @CustomType.Setter
        public Builder uid(String uid) {
            if (uid == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "uid");
            }
            this.uid = uid;
            return this;
        }
        @CustomType.Setter
        public Builder userWalletArtifacts(List<GetDomainsAccountMgmtInfoUserWalletArtifact> userWalletArtifacts) {
            if (userWalletArtifacts == null) {
              throw new MissingRequiredPropertyException("GetDomainsAccountMgmtInfoResult", "userWalletArtifacts");
            }
            this.userWalletArtifacts = userWalletArtifacts;
            return this;
        }
        public Builder userWalletArtifacts(GetDomainsAccountMgmtInfoUserWalletArtifact... userWalletArtifacts) {
            return userWalletArtifacts(List.of(userWalletArtifacts));
        }
        public GetDomainsAccountMgmtInfoResult build() {
            final var _resultValue = new GetDomainsAccountMgmtInfoResult();
            _resultValue.accountMgmtInfoId = accountMgmtInfoId;
            _resultValue.accountType = accountType;
            _resultValue.active = active;
            _resultValue.apps = apps;
            _resultValue.attributeSets = attributeSets;
            _resultValue.attributes = attributes;
            _resultValue.authorization = authorization;
            _resultValue.compartmentOcid = compartmentOcid;
            _resultValue.compositeKey = compositeKey;
            _resultValue.deleteInProgress = deleteInProgress;
            _resultValue.doNotBackFillGrants = doNotBackFillGrants;
            _resultValue.doNotPerformActionOnTarget = doNotPerformActionOnTarget;
            _resultValue.domainOcid = domainOcid;
            _resultValue.favorite = favorite;
            _resultValue.id = id;
            _resultValue.idcsCreatedBies = idcsCreatedBies;
            _resultValue.idcsEndpoint = idcsEndpoint;
            _resultValue.idcsLastModifiedBies = idcsLastModifiedBies;
            _resultValue.idcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            _resultValue.idcsPreventedOperations = idcsPreventedOperations;
            _resultValue.isAccount = isAccount;
            _resultValue.lastAccessed = lastAccessed;
            _resultValue.matchingOwners = matchingOwners;
            _resultValue.metas = metas;
            _resultValue.name = name;
            _resultValue.objectClasses = objectClasses;
            _resultValue.ocid = ocid;
            _resultValue.operationContext = operationContext;
            _resultValue.owners = owners;
            _resultValue.previewOnly = previewOnly;
            _resultValue.resourceTypeSchemaVersion = resourceTypeSchemaVersion;
            _resultValue.resourceTypes = resourceTypes;
            _resultValue.schemas = schemas;
            _resultValue.syncResponse = syncResponse;
            _resultValue.syncSituation = syncSituation;
            _resultValue.syncTimestamp = syncTimestamp;
            _resultValue.tags = tags;
            _resultValue.tenancyOcid = tenancyOcid;
            _resultValue.uid = uid;
            _resultValue.userWalletArtifacts = userWalletArtifacts;
            return _resultValue;
        }
    }
}
