// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Identity.outputs.GetDomainsGrantApp;
import com.pulumi.oci.Identity.outputs.GetDomainsGrantAppEntitlementCollection;
import com.pulumi.oci.Identity.outputs.GetDomainsGrantEntitlement;
import com.pulumi.oci.Identity.outputs.GetDomainsGrantGrantee;
import com.pulumi.oci.Identity.outputs.GetDomainsGrantGrantor;
import com.pulumi.oci.Identity.outputs.GetDomainsGrantIdcsCreatedBy;
import com.pulumi.oci.Identity.outputs.GetDomainsGrantIdcsLastModifiedBy;
import com.pulumi.oci.Identity.outputs.GetDomainsGrantMeta;
import com.pulumi.oci.Identity.outputs.GetDomainsGrantTag;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetDomainsGrantResult {
    /**
     * @return Application-Entitlement-Collection that is being granted. Each Grant must grant either an App or an App-Entitlement-Collection.
     * 
     */
    private List<GetDomainsGrantAppEntitlementCollection> appEntitlementCollections;
    /**
     * @return Application that is being granted. Each Grant must grant either an App or an App-Entitlement-Collection.
     * 
     */
    private List<GetDomainsGrantApp> apps;
    private @Nullable List<String> attributeSets;
    private @Nullable String attributes;
    private @Nullable String authorization;
    /**
     * @return Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
     * 
     */
    private String compartmentOcid;
    /**
     * @return Unique key of grant, composed by combining a subset of app, entitlement, grantee, grantor and grantMechanism.  Used to prevent duplicate Grants.
     * 
     */
    private String compositeKey;
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
     * @return The entitlement or privilege that is being granted
     * 
     */
    private List<GetDomainsGrantEntitlement> entitlements;
    private String grantId;
    /**
     * @return Each value of grantMechanism indicates how (or by what component) some App (or App-Entitlement) was granted. A customer or the UI should use only grantMechanism values that start with &#39;ADMINISTRATOR&#39;:
     * * &#39;ADMINISTRATOR_TO_USER&#39; is for a direct grant to a specific User.
     * * &#39;ADMINISTRATOR_TO_GROUP&#39; is for a grant to a specific Group, which results in indirect grants to Users who are members of that Group.
     * * &#39;ADMINISTRATOR_TO_APP&#39; is for a grant to a specific App.  The grantee (client) App gains access to the granted (server) App.
     * 
     */
    private String grantMechanism;
    /**
     * @return Store granted attribute-values as a string in Javascript Object Notation (JSON) format.
     * 
     */
    private String grantedAttributeValuesJson;
    /**
     * @return Grantee beneficiary. The grantee may be a User, Group, App or DynamicResourceGroup.
     * 
     */
    private List<GetDomainsGrantGrantee> grantees;
    /**
     * @return User conferring the grant to the beneficiary
     * 
     */
    private List<GetDomainsGrantGrantor> grantors;
    /**
     * @return Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider&#39;s entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
     * 
     */
    private String id;
    /**
     * @return The User or App who created the Resource
     * 
     */
    private List<GetDomainsGrantIdcsCreatedBy> idcsCreatedBies;
    private String idcsEndpoint;
    /**
     * @return The User or App who modified the Resource
     * 
     */
    private List<GetDomainsGrantIdcsLastModifiedBy> idcsLastModifiedBies;
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
     * @return If true, this Grant has been fulfilled successfully.
     * 
     */
    private Boolean isFulfilled;
    /**
     * @return A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    private List<GetDomainsGrantMeta> metas;
    /**
     * @return Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     * 
     */
    private String ocid;
    private @Nullable String resourceTypeSchemaVersion;
    /**
     * @return REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \&#34;enterprise\&#34; extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
     * 
     */
    private List<String> schemas;
    /**
     * @return A list of tags on this resource.
     * 
     */
    private List<GetDomainsGrantTag> tags;
    /**
     * @return Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     * 
     */
    private String tenancyOcid;

    private GetDomainsGrantResult() {}
    /**
     * @return Application-Entitlement-Collection that is being granted. Each Grant must grant either an App or an App-Entitlement-Collection.
     * 
     */
    public List<GetDomainsGrantAppEntitlementCollection> appEntitlementCollections() {
        return this.appEntitlementCollections;
    }
    /**
     * @return Application that is being granted. Each Grant must grant either an App or an App-Entitlement-Collection.
     * 
     */
    public List<GetDomainsGrantApp> apps() {
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
     * @return Unique key of grant, composed by combining a subset of app, entitlement, grantee, grantor and grantMechanism.  Used to prevent duplicate Grants.
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
     * @return Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
     * 
     */
    public String domainOcid() {
        return this.domainOcid;
    }
    /**
     * @return The entitlement or privilege that is being granted
     * 
     */
    public List<GetDomainsGrantEntitlement> entitlements() {
        return this.entitlements;
    }
    public String grantId() {
        return this.grantId;
    }
    /**
     * @return Each value of grantMechanism indicates how (or by what component) some App (or App-Entitlement) was granted. A customer or the UI should use only grantMechanism values that start with &#39;ADMINISTRATOR&#39;:
     * * &#39;ADMINISTRATOR_TO_USER&#39; is for a direct grant to a specific User.
     * * &#39;ADMINISTRATOR_TO_GROUP&#39; is for a grant to a specific Group, which results in indirect grants to Users who are members of that Group.
     * * &#39;ADMINISTRATOR_TO_APP&#39; is for a grant to a specific App.  The grantee (client) App gains access to the granted (server) App.
     * 
     */
    public String grantMechanism() {
        return this.grantMechanism;
    }
    /**
     * @return Store granted attribute-values as a string in Javascript Object Notation (JSON) format.
     * 
     */
    public String grantedAttributeValuesJson() {
        return this.grantedAttributeValuesJson;
    }
    /**
     * @return Grantee beneficiary. The grantee may be a User, Group, App or DynamicResourceGroup.
     * 
     */
    public List<GetDomainsGrantGrantee> grantees() {
        return this.grantees;
    }
    /**
     * @return User conferring the grant to the beneficiary
     * 
     */
    public List<GetDomainsGrantGrantor> grantors() {
        return this.grantors;
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
    public List<GetDomainsGrantIdcsCreatedBy> idcsCreatedBies() {
        return this.idcsCreatedBies;
    }
    public String idcsEndpoint() {
        return this.idcsEndpoint;
    }
    /**
     * @return The User or App who modified the Resource
     * 
     */
    public List<GetDomainsGrantIdcsLastModifiedBy> idcsLastModifiedBies() {
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
     * @return If true, this Grant has been fulfilled successfully.
     * 
     */
    public Boolean isFulfilled() {
        return this.isFulfilled;
    }
    /**
     * @return A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    public List<GetDomainsGrantMeta> metas() {
        return this.metas;
    }
    /**
     * @return Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     * 
     */
    public String ocid() {
        return this.ocid;
    }
    public Optional<String> resourceTypeSchemaVersion() {
        return Optional.ofNullable(this.resourceTypeSchemaVersion);
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
    public List<GetDomainsGrantTag> tags() {
        return this.tags;
    }
    /**
     * @return Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     * 
     */
    public String tenancyOcid() {
        return this.tenancyOcid;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsGrantResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDomainsGrantAppEntitlementCollection> appEntitlementCollections;
        private List<GetDomainsGrantApp> apps;
        private @Nullable List<String> attributeSets;
        private @Nullable String attributes;
        private @Nullable String authorization;
        private String compartmentOcid;
        private String compositeKey;
        private Boolean deleteInProgress;
        private String domainOcid;
        private List<GetDomainsGrantEntitlement> entitlements;
        private String grantId;
        private String grantMechanism;
        private String grantedAttributeValuesJson;
        private List<GetDomainsGrantGrantee> grantees;
        private List<GetDomainsGrantGrantor> grantors;
        private String id;
        private List<GetDomainsGrantIdcsCreatedBy> idcsCreatedBies;
        private String idcsEndpoint;
        private List<GetDomainsGrantIdcsLastModifiedBy> idcsLastModifiedBies;
        private String idcsLastUpgradedInRelease;
        private List<String> idcsPreventedOperations;
        private Boolean isFulfilled;
        private List<GetDomainsGrantMeta> metas;
        private String ocid;
        private @Nullable String resourceTypeSchemaVersion;
        private List<String> schemas;
        private List<GetDomainsGrantTag> tags;
        private String tenancyOcid;
        public Builder() {}
        public Builder(GetDomainsGrantResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.appEntitlementCollections = defaults.appEntitlementCollections;
    	      this.apps = defaults.apps;
    	      this.attributeSets = defaults.attributeSets;
    	      this.attributes = defaults.attributes;
    	      this.authorization = defaults.authorization;
    	      this.compartmentOcid = defaults.compartmentOcid;
    	      this.compositeKey = defaults.compositeKey;
    	      this.deleteInProgress = defaults.deleteInProgress;
    	      this.domainOcid = defaults.domainOcid;
    	      this.entitlements = defaults.entitlements;
    	      this.grantId = defaults.grantId;
    	      this.grantMechanism = defaults.grantMechanism;
    	      this.grantedAttributeValuesJson = defaults.grantedAttributeValuesJson;
    	      this.grantees = defaults.grantees;
    	      this.grantors = defaults.grantors;
    	      this.id = defaults.id;
    	      this.idcsCreatedBies = defaults.idcsCreatedBies;
    	      this.idcsEndpoint = defaults.idcsEndpoint;
    	      this.idcsLastModifiedBies = defaults.idcsLastModifiedBies;
    	      this.idcsLastUpgradedInRelease = defaults.idcsLastUpgradedInRelease;
    	      this.idcsPreventedOperations = defaults.idcsPreventedOperations;
    	      this.isFulfilled = defaults.isFulfilled;
    	      this.metas = defaults.metas;
    	      this.ocid = defaults.ocid;
    	      this.resourceTypeSchemaVersion = defaults.resourceTypeSchemaVersion;
    	      this.schemas = defaults.schemas;
    	      this.tags = defaults.tags;
    	      this.tenancyOcid = defaults.tenancyOcid;
        }

        @CustomType.Setter
        public Builder appEntitlementCollections(List<GetDomainsGrantAppEntitlementCollection> appEntitlementCollections) {
            this.appEntitlementCollections = Objects.requireNonNull(appEntitlementCollections);
            return this;
        }
        public Builder appEntitlementCollections(GetDomainsGrantAppEntitlementCollection... appEntitlementCollections) {
            return appEntitlementCollections(List.of(appEntitlementCollections));
        }
        @CustomType.Setter
        public Builder apps(List<GetDomainsGrantApp> apps) {
            this.apps = Objects.requireNonNull(apps);
            return this;
        }
        public Builder apps(GetDomainsGrantApp... apps) {
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
            this.compartmentOcid = Objects.requireNonNull(compartmentOcid);
            return this;
        }
        @CustomType.Setter
        public Builder compositeKey(String compositeKey) {
            this.compositeKey = Objects.requireNonNull(compositeKey);
            return this;
        }
        @CustomType.Setter
        public Builder deleteInProgress(Boolean deleteInProgress) {
            this.deleteInProgress = Objects.requireNonNull(deleteInProgress);
            return this;
        }
        @CustomType.Setter
        public Builder domainOcid(String domainOcid) {
            this.domainOcid = Objects.requireNonNull(domainOcid);
            return this;
        }
        @CustomType.Setter
        public Builder entitlements(List<GetDomainsGrantEntitlement> entitlements) {
            this.entitlements = Objects.requireNonNull(entitlements);
            return this;
        }
        public Builder entitlements(GetDomainsGrantEntitlement... entitlements) {
            return entitlements(List.of(entitlements));
        }
        @CustomType.Setter
        public Builder grantId(String grantId) {
            this.grantId = Objects.requireNonNull(grantId);
            return this;
        }
        @CustomType.Setter
        public Builder grantMechanism(String grantMechanism) {
            this.grantMechanism = Objects.requireNonNull(grantMechanism);
            return this;
        }
        @CustomType.Setter
        public Builder grantedAttributeValuesJson(String grantedAttributeValuesJson) {
            this.grantedAttributeValuesJson = Objects.requireNonNull(grantedAttributeValuesJson);
            return this;
        }
        @CustomType.Setter
        public Builder grantees(List<GetDomainsGrantGrantee> grantees) {
            this.grantees = Objects.requireNonNull(grantees);
            return this;
        }
        public Builder grantees(GetDomainsGrantGrantee... grantees) {
            return grantees(List.of(grantees));
        }
        @CustomType.Setter
        public Builder grantors(List<GetDomainsGrantGrantor> grantors) {
            this.grantors = Objects.requireNonNull(grantors);
            return this;
        }
        public Builder grantors(GetDomainsGrantGrantor... grantors) {
            return grantors(List.of(grantors));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder idcsCreatedBies(List<GetDomainsGrantIdcsCreatedBy> idcsCreatedBies) {
            this.idcsCreatedBies = Objects.requireNonNull(idcsCreatedBies);
            return this;
        }
        public Builder idcsCreatedBies(GetDomainsGrantIdcsCreatedBy... idcsCreatedBies) {
            return idcsCreatedBies(List.of(idcsCreatedBies));
        }
        @CustomType.Setter
        public Builder idcsEndpoint(String idcsEndpoint) {
            this.idcsEndpoint = Objects.requireNonNull(idcsEndpoint);
            return this;
        }
        @CustomType.Setter
        public Builder idcsLastModifiedBies(List<GetDomainsGrantIdcsLastModifiedBy> idcsLastModifiedBies) {
            this.idcsLastModifiedBies = Objects.requireNonNull(idcsLastModifiedBies);
            return this;
        }
        public Builder idcsLastModifiedBies(GetDomainsGrantIdcsLastModifiedBy... idcsLastModifiedBies) {
            return idcsLastModifiedBies(List.of(idcsLastModifiedBies));
        }
        @CustomType.Setter
        public Builder idcsLastUpgradedInRelease(String idcsLastUpgradedInRelease) {
            this.idcsLastUpgradedInRelease = Objects.requireNonNull(idcsLastUpgradedInRelease);
            return this;
        }
        @CustomType.Setter
        public Builder idcsPreventedOperations(List<String> idcsPreventedOperations) {
            this.idcsPreventedOperations = Objects.requireNonNull(idcsPreventedOperations);
            return this;
        }
        public Builder idcsPreventedOperations(String... idcsPreventedOperations) {
            return idcsPreventedOperations(List.of(idcsPreventedOperations));
        }
        @CustomType.Setter
        public Builder isFulfilled(Boolean isFulfilled) {
            this.isFulfilled = Objects.requireNonNull(isFulfilled);
            return this;
        }
        @CustomType.Setter
        public Builder metas(List<GetDomainsGrantMeta> metas) {
            this.metas = Objects.requireNonNull(metas);
            return this;
        }
        public Builder metas(GetDomainsGrantMeta... metas) {
            return metas(List.of(metas));
        }
        @CustomType.Setter
        public Builder ocid(String ocid) {
            this.ocid = Objects.requireNonNull(ocid);
            return this;
        }
        @CustomType.Setter
        public Builder resourceTypeSchemaVersion(@Nullable String resourceTypeSchemaVersion) {
            this.resourceTypeSchemaVersion = resourceTypeSchemaVersion;
            return this;
        }
        @CustomType.Setter
        public Builder schemas(List<String> schemas) {
            this.schemas = Objects.requireNonNull(schemas);
            return this;
        }
        public Builder schemas(String... schemas) {
            return schemas(List.of(schemas));
        }
        @CustomType.Setter
        public Builder tags(List<GetDomainsGrantTag> tags) {
            this.tags = Objects.requireNonNull(tags);
            return this;
        }
        public Builder tags(GetDomainsGrantTag... tags) {
            return tags(List.of(tags));
        }
        @CustomType.Setter
        public Builder tenancyOcid(String tenancyOcid) {
            this.tenancyOcid = Objects.requireNonNull(tenancyOcid);
            return this;
        }
        public GetDomainsGrantResult build() {
            final var o = new GetDomainsGrantResult();
            o.appEntitlementCollections = appEntitlementCollections;
            o.apps = apps;
            o.attributeSets = attributeSets;
            o.attributes = attributes;
            o.authorization = authorization;
            o.compartmentOcid = compartmentOcid;
            o.compositeKey = compositeKey;
            o.deleteInProgress = deleteInProgress;
            o.domainOcid = domainOcid;
            o.entitlements = entitlements;
            o.grantId = grantId;
            o.grantMechanism = grantMechanism;
            o.grantedAttributeValuesJson = grantedAttributeValuesJson;
            o.grantees = grantees;
            o.grantors = grantors;
            o.id = id;
            o.idcsCreatedBies = idcsCreatedBies;
            o.idcsEndpoint = idcsEndpoint;
            o.idcsLastModifiedBies = idcsLastModifiedBies;
            o.idcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            o.idcsPreventedOperations = idcsPreventedOperations;
            o.isFulfilled = isFulfilled;
            o.metas = metas;
            o.ocid = ocid;
            o.resourceTypeSchemaVersion = resourceTypeSchemaVersion;
            o.schemas = schemas;
            o.tags = tags;
            o.tenancyOcid = tenancyOcid;
            return o;
        }
    }
}