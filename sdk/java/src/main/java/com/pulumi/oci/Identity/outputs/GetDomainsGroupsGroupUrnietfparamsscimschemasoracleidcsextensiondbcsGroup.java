// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Identity.outputs.GetDomainsGroupsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupDomainLevelSchemaName;
import com.pulumi.oci.Identity.outputs.GetDomainsGroupsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupInstanceLevelSchemaName;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDomainsGroupsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroup {
    /**
     * @return DBCS Domain-level schema-name.  This attribute refers implicitly to a value of &#39;domainLevelSchemaNames&#39; for a particular DB Domain.
     * 
     */
    private String domainLevelSchema;
    /**
     * @return DBCS Domain-level schema-names. Each value is specific to a DB Domain.
     * 
     */
    private List<GetDomainsGroupsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupDomainLevelSchemaName> domainLevelSchemaNames;
    /**
     * @return DBCS instance-level schema-name. This attribute refers implicitly to a value of &#39;instanceLevelSchemaNames&#39; for a particular DB Instance.
     * 
     */
    private String instanceLevelSchema;
    /**
     * @return DBCS instance-level schema-names. Each schema-name is specific to a DB Instance.
     * 
     */
    private List<GetDomainsGroupsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupInstanceLevelSchemaName> instanceLevelSchemaNames;

    private GetDomainsGroupsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroup() {}
    /**
     * @return DBCS Domain-level schema-name.  This attribute refers implicitly to a value of &#39;domainLevelSchemaNames&#39; for a particular DB Domain.
     * 
     */
    public String domainLevelSchema() {
        return this.domainLevelSchema;
    }
    /**
     * @return DBCS Domain-level schema-names. Each value is specific to a DB Domain.
     * 
     */
    public List<GetDomainsGroupsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupDomainLevelSchemaName> domainLevelSchemaNames() {
        return this.domainLevelSchemaNames;
    }
    /**
     * @return DBCS instance-level schema-name. This attribute refers implicitly to a value of &#39;instanceLevelSchemaNames&#39; for a particular DB Instance.
     * 
     */
    public String instanceLevelSchema() {
        return this.instanceLevelSchema;
    }
    /**
     * @return DBCS instance-level schema-names. Each schema-name is specific to a DB Instance.
     * 
     */
    public List<GetDomainsGroupsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupInstanceLevelSchemaName> instanceLevelSchemaNames() {
        return this.instanceLevelSchemaNames;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsGroupsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroup defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String domainLevelSchema;
        private List<GetDomainsGroupsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupDomainLevelSchemaName> domainLevelSchemaNames;
        private String instanceLevelSchema;
        private List<GetDomainsGroupsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupInstanceLevelSchemaName> instanceLevelSchemaNames;
        public Builder() {}
        public Builder(GetDomainsGroupsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroup defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.domainLevelSchema = defaults.domainLevelSchema;
    	      this.domainLevelSchemaNames = defaults.domainLevelSchemaNames;
    	      this.instanceLevelSchema = defaults.instanceLevelSchema;
    	      this.instanceLevelSchemaNames = defaults.instanceLevelSchemaNames;
        }

        @CustomType.Setter
        public Builder domainLevelSchema(String domainLevelSchema) {
            this.domainLevelSchema = Objects.requireNonNull(domainLevelSchema);
            return this;
        }
        @CustomType.Setter
        public Builder domainLevelSchemaNames(List<GetDomainsGroupsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupDomainLevelSchemaName> domainLevelSchemaNames) {
            this.domainLevelSchemaNames = Objects.requireNonNull(domainLevelSchemaNames);
            return this;
        }
        public Builder domainLevelSchemaNames(GetDomainsGroupsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupDomainLevelSchemaName... domainLevelSchemaNames) {
            return domainLevelSchemaNames(List.of(domainLevelSchemaNames));
        }
        @CustomType.Setter
        public Builder instanceLevelSchema(String instanceLevelSchema) {
            this.instanceLevelSchema = Objects.requireNonNull(instanceLevelSchema);
            return this;
        }
        @CustomType.Setter
        public Builder instanceLevelSchemaNames(List<GetDomainsGroupsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupInstanceLevelSchemaName> instanceLevelSchemaNames) {
            this.instanceLevelSchemaNames = Objects.requireNonNull(instanceLevelSchemaNames);
            return this;
        }
        public Builder instanceLevelSchemaNames(GetDomainsGroupsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupInstanceLevelSchemaName... instanceLevelSchemaNames) {
            return instanceLevelSchemaNames(List.of(instanceLevelSchemaNames));
        }
        public GetDomainsGroupsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroup build() {
            final var o = new GetDomainsGroupsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroup();
            o.domainLevelSchema = domainLevelSchema;
            o.domainLevelSchemaNames = domainLevelSchemaNames;
            o.instanceLevelSchema = instanceLevelSchema;
            o.instanceLevelSchemaNames = instanceLevelSchemaNames;
            return o;
        }
    }
}