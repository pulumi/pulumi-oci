// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Identity.outputs.GetDomainsUserAttributesSettingAttributeSetting;
import com.pulumi.oci.Identity.outputs.GetDomainsUserAttributesSettingIdcsCreatedBy;
import com.pulumi.oci.Identity.outputs.GetDomainsUserAttributesSettingIdcsLastModifiedBy;
import com.pulumi.oci.Identity.outputs.GetDomainsUserAttributesSettingMeta;
import com.pulumi.oci.Identity.outputs.GetDomainsUserAttributesSettingTag;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetDomainsUserAttributesSettingResult {
    private @Nullable List<String> attributeSets;
    /**
     * @return User Schema Attribute Settings
     * 
     */
    private List<GetDomainsUserAttributesSettingAttributeSetting> attributeSettings;
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
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The User or App who created the Resource
     * 
     */
    private List<GetDomainsUserAttributesSettingIdcsCreatedBy> idcsCreatedBies;
    private String idcsEndpoint;
    /**
     * @return The User or App who modified the Resource
     * 
     */
    private List<GetDomainsUserAttributesSettingIdcsLastModifiedBy> idcsLastModifiedBies;
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
     * @return A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    private List<GetDomainsUserAttributesSettingMeta> metas;
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
    private List<GetDomainsUserAttributesSettingTag> tags;
    /**
     * @return Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     * 
     */
    private String tenancyOcid;
    private String userAttributesSettingId;

    private GetDomainsUserAttributesSettingResult() {}
    public List<String> attributeSets() {
        return this.attributeSets == null ? List.of() : this.attributeSets;
    }
    /**
     * @return User Schema Attribute Settings
     * 
     */
    public List<GetDomainsUserAttributesSettingAttributeSetting> attributeSettings() {
        return this.attributeSettings;
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
    public List<GetDomainsUserAttributesSettingIdcsCreatedBy> idcsCreatedBies() {
        return this.idcsCreatedBies;
    }
    public String idcsEndpoint() {
        return this.idcsEndpoint;
    }
    /**
     * @return The User or App who modified the Resource
     * 
     */
    public List<GetDomainsUserAttributesSettingIdcsLastModifiedBy> idcsLastModifiedBies() {
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
     * @return A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    public List<GetDomainsUserAttributesSettingMeta> metas() {
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
    public List<GetDomainsUserAttributesSettingTag> tags() {
        return this.tags;
    }
    /**
     * @return Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     * 
     */
    public String tenancyOcid() {
        return this.tenancyOcid;
    }
    public String userAttributesSettingId() {
        return this.userAttributesSettingId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsUserAttributesSettingResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<String> attributeSets;
        private List<GetDomainsUserAttributesSettingAttributeSetting> attributeSettings;
        private @Nullable String attributes;
        private @Nullable String authorization;
        private String compartmentOcid;
        private Boolean deleteInProgress;
        private String domainOcid;
        private String id;
        private List<GetDomainsUserAttributesSettingIdcsCreatedBy> idcsCreatedBies;
        private String idcsEndpoint;
        private List<GetDomainsUserAttributesSettingIdcsLastModifiedBy> idcsLastModifiedBies;
        private String idcsLastUpgradedInRelease;
        private List<String> idcsPreventedOperations;
        private List<GetDomainsUserAttributesSettingMeta> metas;
        private String ocid;
        private @Nullable String resourceTypeSchemaVersion;
        private List<String> schemas;
        private List<GetDomainsUserAttributesSettingTag> tags;
        private String tenancyOcid;
        private String userAttributesSettingId;
        public Builder() {}
        public Builder(GetDomainsUserAttributesSettingResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.attributeSets = defaults.attributeSets;
    	      this.attributeSettings = defaults.attributeSettings;
    	      this.attributes = defaults.attributes;
    	      this.authorization = defaults.authorization;
    	      this.compartmentOcid = defaults.compartmentOcid;
    	      this.deleteInProgress = defaults.deleteInProgress;
    	      this.domainOcid = defaults.domainOcid;
    	      this.id = defaults.id;
    	      this.idcsCreatedBies = defaults.idcsCreatedBies;
    	      this.idcsEndpoint = defaults.idcsEndpoint;
    	      this.idcsLastModifiedBies = defaults.idcsLastModifiedBies;
    	      this.idcsLastUpgradedInRelease = defaults.idcsLastUpgradedInRelease;
    	      this.idcsPreventedOperations = defaults.idcsPreventedOperations;
    	      this.metas = defaults.metas;
    	      this.ocid = defaults.ocid;
    	      this.resourceTypeSchemaVersion = defaults.resourceTypeSchemaVersion;
    	      this.schemas = defaults.schemas;
    	      this.tags = defaults.tags;
    	      this.tenancyOcid = defaults.tenancyOcid;
    	      this.userAttributesSettingId = defaults.userAttributesSettingId;
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
        public Builder attributeSettings(List<GetDomainsUserAttributesSettingAttributeSetting> attributeSettings) {
            this.attributeSettings = Objects.requireNonNull(attributeSettings);
            return this;
        }
        public Builder attributeSettings(GetDomainsUserAttributesSettingAttributeSetting... attributeSettings) {
            return attributeSettings(List.of(attributeSettings));
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
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder idcsCreatedBies(List<GetDomainsUserAttributesSettingIdcsCreatedBy> idcsCreatedBies) {
            this.idcsCreatedBies = Objects.requireNonNull(idcsCreatedBies);
            return this;
        }
        public Builder idcsCreatedBies(GetDomainsUserAttributesSettingIdcsCreatedBy... idcsCreatedBies) {
            return idcsCreatedBies(List.of(idcsCreatedBies));
        }
        @CustomType.Setter
        public Builder idcsEndpoint(String idcsEndpoint) {
            this.idcsEndpoint = Objects.requireNonNull(idcsEndpoint);
            return this;
        }
        @CustomType.Setter
        public Builder idcsLastModifiedBies(List<GetDomainsUserAttributesSettingIdcsLastModifiedBy> idcsLastModifiedBies) {
            this.idcsLastModifiedBies = Objects.requireNonNull(idcsLastModifiedBies);
            return this;
        }
        public Builder idcsLastModifiedBies(GetDomainsUserAttributesSettingIdcsLastModifiedBy... idcsLastModifiedBies) {
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
        public Builder metas(List<GetDomainsUserAttributesSettingMeta> metas) {
            this.metas = Objects.requireNonNull(metas);
            return this;
        }
        public Builder metas(GetDomainsUserAttributesSettingMeta... metas) {
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
        public Builder tags(List<GetDomainsUserAttributesSettingTag> tags) {
            this.tags = Objects.requireNonNull(tags);
            return this;
        }
        public Builder tags(GetDomainsUserAttributesSettingTag... tags) {
            return tags(List.of(tags));
        }
        @CustomType.Setter
        public Builder tenancyOcid(String tenancyOcid) {
            this.tenancyOcid = Objects.requireNonNull(tenancyOcid);
            return this;
        }
        @CustomType.Setter
        public Builder userAttributesSettingId(String userAttributesSettingId) {
            this.userAttributesSettingId = Objects.requireNonNull(userAttributesSettingId);
            return this;
        }
        public GetDomainsUserAttributesSettingResult build() {
            final var o = new GetDomainsUserAttributesSettingResult();
            o.attributeSets = attributeSets;
            o.attributeSettings = attributeSettings;
            o.attributes = attributes;
            o.authorization = authorization;
            o.compartmentOcid = compartmentOcid;
            o.deleteInProgress = deleteInProgress;
            o.domainOcid = domainOcid;
            o.id = id;
            o.idcsCreatedBies = idcsCreatedBies;
            o.idcsEndpoint = idcsEndpoint;
            o.idcsLastModifiedBies = idcsLastModifiedBies;
            o.idcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            o.idcsPreventedOperations = idcsPreventedOperations;
            o.metas = metas;
            o.ocid = ocid;
            o.resourceTypeSchemaVersion = resourceTypeSchemaVersion;
            o.schemas = schemas;
            o.tags = tags;
            o.tenancyOcid = tenancyOcid;
            o.userAttributesSettingId = userAttributesSettingId;
            return o;
        }
    }
}