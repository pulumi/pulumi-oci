// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupDomainLevelSchemaNameArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupDomainLevelSchemaNameArgs Empty = new DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupDomainLevelSchemaNameArgs();

    /**
     * (Updatable) DBCS Domain Name
     * 
     */
    @Import(name="domainName", required=true)
    private Output<String> domainName;

    /**
     * @return (Updatable) DBCS Domain Name
     * 
     */
    public Output<String> domainName() {
        return this.domainName;
    }

    /**
     * (Updatable) The DBCS schema-name granted to this Group for the DB instance that &#39;dbInstanceId&#39; specifies.
     * 
     */
    @Import(name="schemaName", required=true)
    private Output<String> schemaName;

    /**
     * @return (Updatable) The DBCS schema-name granted to this Group for the DB instance that &#39;dbInstanceId&#39; specifies.
     * 
     */
    public Output<String> schemaName() {
        return this.schemaName;
    }

    private DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupDomainLevelSchemaNameArgs() {}

    private DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupDomainLevelSchemaNameArgs(DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupDomainLevelSchemaNameArgs $) {
        this.domainName = $.domainName;
        this.schemaName = $.schemaName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupDomainLevelSchemaNameArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupDomainLevelSchemaNameArgs $;

        public Builder() {
            $ = new DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupDomainLevelSchemaNameArgs();
        }

        public Builder(DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupDomainLevelSchemaNameArgs defaults) {
            $ = new DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupDomainLevelSchemaNameArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param domainName (Updatable) DBCS Domain Name
         * 
         * @return builder
         * 
         */
        public Builder domainName(Output<String> domainName) {
            $.domainName = domainName;
            return this;
        }

        /**
         * @param domainName (Updatable) DBCS Domain Name
         * 
         * @return builder
         * 
         */
        public Builder domainName(String domainName) {
            return domainName(Output.of(domainName));
        }

        /**
         * @param schemaName (Updatable) The DBCS schema-name granted to this Group for the DB instance that &#39;dbInstanceId&#39; specifies.
         * 
         * @return builder
         * 
         */
        public Builder schemaName(Output<String> schemaName) {
            $.schemaName = schemaName;
            return this;
        }

        /**
         * @param schemaName (Updatable) The DBCS schema-name granted to this Group for the DB instance that &#39;dbInstanceId&#39; specifies.
         * 
         * @return builder
         * 
         */
        public Builder schemaName(String schemaName) {
            return schemaName(Output.of(schemaName));
        }

        public DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupDomainLevelSchemaNameArgs build() {
            $.domainName = Objects.requireNonNull($.domainName, "expected parameter 'domainName' to be non-null");
            $.schemaName = Objects.requireNonNull($.schemaName, "expected parameter 'schemaName' to be non-null");
            return $;
        }
    }

}