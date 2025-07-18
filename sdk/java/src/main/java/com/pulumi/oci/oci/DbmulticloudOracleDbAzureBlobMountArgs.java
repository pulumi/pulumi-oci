// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.oci;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DbmulticloudOracleDbAzureBlobMountArgs extends com.pulumi.resources.ResourceArgs {

    public static final DbmulticloudOracleDbAzureBlobMountArgs Empty = new DbmulticloudOracleDbAzureBlobMountArgs();

    /**
     * (Updatable) The OCID of the compartment that contains VMs where to mount Azure Container.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment that contains VMs where to mount Azure Container.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) Oracle DB Azure Blob Mount Resource name.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) Oracle DB Azure Blob Mount Resource name.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) The OCID of the Oracle DB Azure Blob Container Resource.
     * 
     */
    @Import(name="oracleDbAzureBlobContainerId", required=true)
    private Output<String> oracleDbAzureBlobContainerId;

    /**
     * @return (Updatable) The OCID of the Oracle DB Azure Blob Container Resource.
     * 
     */
    public Output<String> oracleDbAzureBlobContainerId() {
        return this.oracleDbAzureBlobContainerId;
    }

    /**
     * (Updatable) The OCID of the Oracle DB Azure Connector Resource.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="oracleDbAzureConnectorId", required=true)
    private Output<String> oracleDbAzureConnectorId;

    /**
     * @return (Updatable) The OCID of the Oracle DB Azure Connector Resource.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> oracleDbAzureConnectorId() {
        return this.oracleDbAzureConnectorId;
    }

    private DbmulticloudOracleDbAzureBlobMountArgs() {}

    private DbmulticloudOracleDbAzureBlobMountArgs(DbmulticloudOracleDbAzureBlobMountArgs $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.oracleDbAzureBlobContainerId = $.oracleDbAzureBlobContainerId;
        this.oracleDbAzureConnectorId = $.oracleDbAzureConnectorId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DbmulticloudOracleDbAzureBlobMountArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DbmulticloudOracleDbAzureBlobMountArgs $;

        public Builder() {
            $ = new DbmulticloudOracleDbAzureBlobMountArgs();
        }

        public Builder(DbmulticloudOracleDbAzureBlobMountArgs defaults) {
            $ = new DbmulticloudOracleDbAzureBlobMountArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment that contains VMs where to mount Azure Container.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment that contains VMs where to mount Azure Container.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) Oracle DB Azure Blob Mount Resource name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Oracle DB Azure Blob Mount Resource name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param oracleDbAzureBlobContainerId (Updatable) The OCID of the Oracle DB Azure Blob Container Resource.
         * 
         * @return builder
         * 
         */
        public Builder oracleDbAzureBlobContainerId(Output<String> oracleDbAzureBlobContainerId) {
            $.oracleDbAzureBlobContainerId = oracleDbAzureBlobContainerId;
            return this;
        }

        /**
         * @param oracleDbAzureBlobContainerId (Updatable) The OCID of the Oracle DB Azure Blob Container Resource.
         * 
         * @return builder
         * 
         */
        public Builder oracleDbAzureBlobContainerId(String oracleDbAzureBlobContainerId) {
            return oracleDbAzureBlobContainerId(Output.of(oracleDbAzureBlobContainerId));
        }

        /**
         * @param oracleDbAzureConnectorId (Updatable) The OCID of the Oracle DB Azure Connector Resource.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder oracleDbAzureConnectorId(Output<String> oracleDbAzureConnectorId) {
            $.oracleDbAzureConnectorId = oracleDbAzureConnectorId;
            return this;
        }

        /**
         * @param oracleDbAzureConnectorId (Updatable) The OCID of the Oracle DB Azure Connector Resource.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder oracleDbAzureConnectorId(String oracleDbAzureConnectorId) {
            return oracleDbAzureConnectorId(Output.of(oracleDbAzureConnectorId));
        }

        public DbmulticloudOracleDbAzureBlobMountArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("DbmulticloudOracleDbAzureBlobMountArgs", "compartmentId");
            }
            if ($.displayName == null) {
                throw new MissingRequiredPropertyException("DbmulticloudOracleDbAzureBlobMountArgs", "displayName");
            }
            if ($.oracleDbAzureBlobContainerId == null) {
                throw new MissingRequiredPropertyException("DbmulticloudOracleDbAzureBlobMountArgs", "oracleDbAzureBlobContainerId");
            }
            if ($.oracleDbAzureConnectorId == null) {
                throw new MissingRequiredPropertyException("DbmulticloudOracleDbAzureBlobMountArgs", "oracleDbAzureConnectorId");
            }
            return $;
        }
    }

}
