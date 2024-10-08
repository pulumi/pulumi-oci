// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Identity.outputs.GetDomainsMyGroupsMyGroupIdcsCreatedBy;
import com.pulumi.oci.Identity.outputs.GetDomainsMyGroupsMyGroupIdcsLastModifiedBy;
import com.pulumi.oci.Identity.outputs.GetDomainsMyGroupsMyGroupMember;
import com.pulumi.oci.Identity.outputs.GetDomainsMyGroupsMyGroupMeta;
import com.pulumi.oci.Identity.outputs.GetDomainsMyGroupsMyGroupTag;
import com.pulumi.oci.Identity.outputs.GetDomainsMyGroupsMyGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroup;
import com.pulumi.oci.Identity.outputs.GetDomainsMyGroupsMyGroupUrnietfparamsscimschemasoracleidcsextensionposixGroup;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDomainsMyGroupsMyGroup {
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
     * @return The Group display name.
     * 
     */
    private String displayName;
    /**
     * @return Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
     * 
     */
    private String domainOcid;
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
    private List<GetDomainsMyGroupsMyGroupIdcsCreatedBy> idcsCreatedBies;
    /**
     * @return The User or App who modified the Resource
     * 
     */
    private List<GetDomainsMyGroupsMyGroupIdcsLastModifiedBy> idcsLastModifiedBies;
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
     * @return The group members. &lt;b&gt;Important:&lt;/b&gt; When requesting group members, a maximum of 10,000 members can be returned in a single request. If the response contains more than 10,000 members, the request will fail. Use &#39;startIndex&#39; and &#39;count&#39; to return members in pages instead of in a single response, for example: #attributes=members[startIndex=1%26count=10]. This REST API is SCIM compliant.
     * 
     */
    private List<GetDomainsMyGroupsMyGroupMember> members;
    /**
     * @return A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    private List<GetDomainsMyGroupsMyGroupMeta> metas;
    /**
     * @return A human readable name for the group as defined by the Service Consumer.
     * 
     */
    private String nonUniqueDisplayName;
    /**
     * @return Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     * 
     */
    private String ocid;
    /**
     * @return The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior. REQUIRED.
     * 
     */
    private List<String> schemas;
    /**
     * @return A list of tags on this resource.
     * 
     */
    private List<GetDomainsMyGroupsMyGroupTag> tags;
    /**
     * @return Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     * 
     */
    private String tenancyOcid;
    /**
     * @return Oracle Identity Cloud Service Group
     * 
     */
    private List<GetDomainsMyGroupsMyGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroup> urnietfparamsscimschemasoracleidcsextensiongroupGroups;
    /**
     * @return POSIX Group extension
     * 
     */
    private List<GetDomainsMyGroupsMyGroupUrnietfparamsscimschemasoracleidcsextensionposixGroup> urnietfparamsscimschemasoracleidcsextensionposixGroups;

    private GetDomainsMyGroupsMyGroup() {}
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
     * @return The Group display name.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
     * 
     */
    public String domainOcid() {
        return this.domainOcid;
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
    public List<GetDomainsMyGroupsMyGroupIdcsCreatedBy> idcsCreatedBies() {
        return this.idcsCreatedBies;
    }
    /**
     * @return The User or App who modified the Resource
     * 
     */
    public List<GetDomainsMyGroupsMyGroupIdcsLastModifiedBy> idcsLastModifiedBies() {
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
     * @return The group members. &lt;b&gt;Important:&lt;/b&gt; When requesting group members, a maximum of 10,000 members can be returned in a single request. If the response contains more than 10,000 members, the request will fail. Use &#39;startIndex&#39; and &#39;count&#39; to return members in pages instead of in a single response, for example: #attributes=members[startIndex=1%26count=10]. This REST API is SCIM compliant.
     * 
     */
    public List<GetDomainsMyGroupsMyGroupMember> members() {
        return this.members;
    }
    /**
     * @return A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    public List<GetDomainsMyGroupsMyGroupMeta> metas() {
        return this.metas;
    }
    /**
     * @return A human readable name for the group as defined by the Service Consumer.
     * 
     */
    public String nonUniqueDisplayName() {
        return this.nonUniqueDisplayName;
    }
    /**
     * @return Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     * 
     */
    public String ocid() {
        return this.ocid;
    }
    /**
     * @return The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior. REQUIRED.
     * 
     */
    public List<String> schemas() {
        return this.schemas;
    }
    /**
     * @return A list of tags on this resource.
     * 
     */
    public List<GetDomainsMyGroupsMyGroupTag> tags() {
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
     * @return Oracle Identity Cloud Service Group
     * 
     */
    public List<GetDomainsMyGroupsMyGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroup> urnietfparamsscimschemasoracleidcsextensiongroupGroups() {
        return this.urnietfparamsscimschemasoracleidcsextensiongroupGroups;
    }
    /**
     * @return POSIX Group extension
     * 
     */
    public List<GetDomainsMyGroupsMyGroupUrnietfparamsscimschemasoracleidcsextensionposixGroup> urnietfparamsscimschemasoracleidcsextensionposixGroups() {
        return this.urnietfparamsscimschemasoracleidcsextensionposixGroups;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsMyGroupsMyGroup defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentOcid;
        private Boolean deleteInProgress;
        private String displayName;
        private String domainOcid;
        private String externalId;
        private String id;
        private List<GetDomainsMyGroupsMyGroupIdcsCreatedBy> idcsCreatedBies;
        private List<GetDomainsMyGroupsMyGroupIdcsLastModifiedBy> idcsLastModifiedBies;
        private String idcsLastUpgradedInRelease;
        private List<String> idcsPreventedOperations;
        private List<GetDomainsMyGroupsMyGroupMember> members;
        private List<GetDomainsMyGroupsMyGroupMeta> metas;
        private String nonUniqueDisplayName;
        private String ocid;
        private List<String> schemas;
        private List<GetDomainsMyGroupsMyGroupTag> tags;
        private String tenancyOcid;
        private List<GetDomainsMyGroupsMyGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroup> urnietfparamsscimschemasoracleidcsextensiongroupGroups;
        private List<GetDomainsMyGroupsMyGroupUrnietfparamsscimschemasoracleidcsextensionposixGroup> urnietfparamsscimschemasoracleidcsextensionposixGroups;
        public Builder() {}
        public Builder(GetDomainsMyGroupsMyGroup defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentOcid = defaults.compartmentOcid;
    	      this.deleteInProgress = defaults.deleteInProgress;
    	      this.displayName = defaults.displayName;
    	      this.domainOcid = defaults.domainOcid;
    	      this.externalId = defaults.externalId;
    	      this.id = defaults.id;
    	      this.idcsCreatedBies = defaults.idcsCreatedBies;
    	      this.idcsLastModifiedBies = defaults.idcsLastModifiedBies;
    	      this.idcsLastUpgradedInRelease = defaults.idcsLastUpgradedInRelease;
    	      this.idcsPreventedOperations = defaults.idcsPreventedOperations;
    	      this.members = defaults.members;
    	      this.metas = defaults.metas;
    	      this.nonUniqueDisplayName = defaults.nonUniqueDisplayName;
    	      this.ocid = defaults.ocid;
    	      this.schemas = defaults.schemas;
    	      this.tags = defaults.tags;
    	      this.tenancyOcid = defaults.tenancyOcid;
    	      this.urnietfparamsscimschemasoracleidcsextensiongroupGroups = defaults.urnietfparamsscimschemasoracleidcsextensiongroupGroups;
    	      this.urnietfparamsscimschemasoracleidcsextensionposixGroups = defaults.urnietfparamsscimschemasoracleidcsextensionposixGroups;
        }

        @CustomType.Setter
        public Builder compartmentOcid(String compartmentOcid) {
            if (compartmentOcid == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyGroupsMyGroup", "compartmentOcid");
            }
            this.compartmentOcid = compartmentOcid;
            return this;
        }
        @CustomType.Setter
        public Builder deleteInProgress(Boolean deleteInProgress) {
            if (deleteInProgress == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyGroupsMyGroup", "deleteInProgress");
            }
            this.deleteInProgress = deleteInProgress;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyGroupsMyGroup", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder domainOcid(String domainOcid) {
            if (domainOcid == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyGroupsMyGroup", "domainOcid");
            }
            this.domainOcid = domainOcid;
            return this;
        }
        @CustomType.Setter
        public Builder externalId(String externalId) {
            if (externalId == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyGroupsMyGroup", "externalId");
            }
            this.externalId = externalId;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyGroupsMyGroup", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder idcsCreatedBies(List<GetDomainsMyGroupsMyGroupIdcsCreatedBy> idcsCreatedBies) {
            if (idcsCreatedBies == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyGroupsMyGroup", "idcsCreatedBies");
            }
            this.idcsCreatedBies = idcsCreatedBies;
            return this;
        }
        public Builder idcsCreatedBies(GetDomainsMyGroupsMyGroupIdcsCreatedBy... idcsCreatedBies) {
            return idcsCreatedBies(List.of(idcsCreatedBies));
        }
        @CustomType.Setter
        public Builder idcsLastModifiedBies(List<GetDomainsMyGroupsMyGroupIdcsLastModifiedBy> idcsLastModifiedBies) {
            if (idcsLastModifiedBies == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyGroupsMyGroup", "idcsLastModifiedBies");
            }
            this.idcsLastModifiedBies = idcsLastModifiedBies;
            return this;
        }
        public Builder idcsLastModifiedBies(GetDomainsMyGroupsMyGroupIdcsLastModifiedBy... idcsLastModifiedBies) {
            return idcsLastModifiedBies(List.of(idcsLastModifiedBies));
        }
        @CustomType.Setter
        public Builder idcsLastUpgradedInRelease(String idcsLastUpgradedInRelease) {
            if (idcsLastUpgradedInRelease == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyGroupsMyGroup", "idcsLastUpgradedInRelease");
            }
            this.idcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            return this;
        }
        @CustomType.Setter
        public Builder idcsPreventedOperations(List<String> idcsPreventedOperations) {
            if (idcsPreventedOperations == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyGroupsMyGroup", "idcsPreventedOperations");
            }
            this.idcsPreventedOperations = idcsPreventedOperations;
            return this;
        }
        public Builder idcsPreventedOperations(String... idcsPreventedOperations) {
            return idcsPreventedOperations(List.of(idcsPreventedOperations));
        }
        @CustomType.Setter
        public Builder members(List<GetDomainsMyGroupsMyGroupMember> members) {
            if (members == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyGroupsMyGroup", "members");
            }
            this.members = members;
            return this;
        }
        public Builder members(GetDomainsMyGroupsMyGroupMember... members) {
            return members(List.of(members));
        }
        @CustomType.Setter
        public Builder metas(List<GetDomainsMyGroupsMyGroupMeta> metas) {
            if (metas == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyGroupsMyGroup", "metas");
            }
            this.metas = metas;
            return this;
        }
        public Builder metas(GetDomainsMyGroupsMyGroupMeta... metas) {
            return metas(List.of(metas));
        }
        @CustomType.Setter
        public Builder nonUniqueDisplayName(String nonUniqueDisplayName) {
            if (nonUniqueDisplayName == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyGroupsMyGroup", "nonUniqueDisplayName");
            }
            this.nonUniqueDisplayName = nonUniqueDisplayName;
            return this;
        }
        @CustomType.Setter
        public Builder ocid(String ocid) {
            if (ocid == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyGroupsMyGroup", "ocid");
            }
            this.ocid = ocid;
            return this;
        }
        @CustomType.Setter
        public Builder schemas(List<String> schemas) {
            if (schemas == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyGroupsMyGroup", "schemas");
            }
            this.schemas = schemas;
            return this;
        }
        public Builder schemas(String... schemas) {
            return schemas(List.of(schemas));
        }
        @CustomType.Setter
        public Builder tags(List<GetDomainsMyGroupsMyGroupTag> tags) {
            if (tags == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyGroupsMyGroup", "tags");
            }
            this.tags = tags;
            return this;
        }
        public Builder tags(GetDomainsMyGroupsMyGroupTag... tags) {
            return tags(List.of(tags));
        }
        @CustomType.Setter
        public Builder tenancyOcid(String tenancyOcid) {
            if (tenancyOcid == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyGroupsMyGroup", "tenancyOcid");
            }
            this.tenancyOcid = tenancyOcid;
            return this;
        }
        @CustomType.Setter
        public Builder urnietfparamsscimschemasoracleidcsextensiongroupGroups(List<GetDomainsMyGroupsMyGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroup> urnietfparamsscimschemasoracleidcsextensiongroupGroups) {
            if (urnietfparamsscimschemasoracleidcsextensiongroupGroups == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyGroupsMyGroup", "urnietfparamsscimschemasoracleidcsextensiongroupGroups");
            }
            this.urnietfparamsscimschemasoracleidcsextensiongroupGroups = urnietfparamsscimschemasoracleidcsextensiongroupGroups;
            return this;
        }
        public Builder urnietfparamsscimschemasoracleidcsextensiongroupGroups(GetDomainsMyGroupsMyGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroup... urnietfparamsscimschemasoracleidcsextensiongroupGroups) {
            return urnietfparamsscimschemasoracleidcsextensiongroupGroups(List.of(urnietfparamsscimschemasoracleidcsextensiongroupGroups));
        }
        @CustomType.Setter
        public Builder urnietfparamsscimschemasoracleidcsextensionposixGroups(List<GetDomainsMyGroupsMyGroupUrnietfparamsscimschemasoracleidcsextensionposixGroup> urnietfparamsscimschemasoracleidcsextensionposixGroups) {
            if (urnietfparamsscimschemasoracleidcsextensionposixGroups == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyGroupsMyGroup", "urnietfparamsscimschemasoracleidcsextensionposixGroups");
            }
            this.urnietfparamsscimschemasoracleidcsextensionposixGroups = urnietfparamsscimschemasoracleidcsextensionposixGroups;
            return this;
        }
        public Builder urnietfparamsscimschemasoracleidcsextensionposixGroups(GetDomainsMyGroupsMyGroupUrnietfparamsscimschemasoracleidcsextensionposixGroup... urnietfparamsscimschemasoracleidcsextensionposixGroups) {
            return urnietfparamsscimschemasoracleidcsextensionposixGroups(List.of(urnietfparamsscimschemasoracleidcsextensionposixGroups));
        }
        public GetDomainsMyGroupsMyGroup build() {
            final var _resultValue = new GetDomainsMyGroupsMyGroup();
            _resultValue.compartmentOcid = compartmentOcid;
            _resultValue.deleteInProgress = deleteInProgress;
            _resultValue.displayName = displayName;
            _resultValue.domainOcid = domainOcid;
            _resultValue.externalId = externalId;
            _resultValue.id = id;
            _resultValue.idcsCreatedBies = idcsCreatedBies;
            _resultValue.idcsLastModifiedBies = idcsLastModifiedBies;
            _resultValue.idcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            _resultValue.idcsPreventedOperations = idcsPreventedOperations;
            _resultValue.members = members;
            _resultValue.metas = metas;
            _resultValue.nonUniqueDisplayName = nonUniqueDisplayName;
            _resultValue.ocid = ocid;
            _resultValue.schemas = schemas;
            _resultValue.tags = tags;
            _resultValue.tenancyOcid = tenancyOcid;
            _resultValue.urnietfparamsscimschemasoracleidcsextensiongroupGroups = urnietfparamsscimschemasoracleidcsextensiongroupGroups;
            _resultValue.urnietfparamsscimschemasoracleidcsextensionposixGroups = urnietfparamsscimschemasoracleidcsextensionposixGroups;
            return _resultValue;
        }
    }
}
