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


public final class DbmulticloudOracleDbAzureBlobContainerArgs extends com.pulumi.resources.ResourceArgs {

    public static final DbmulticloudOracleDbAzureBlobContainerArgs Empty = new DbmulticloudOracleDbAzureBlobContainerArgs();

    /**
     * (Updatable) Azure Storage Account Name.
     * 
     */
    @Import(name="azureStorageAccountName", required=true)
    private Output<String> azureStorageAccountName;

    /**
     * @return (Updatable) Azure Storage Account Name.
     * 
     */
    public Output<String> azureStorageAccountName() {
        return this.azureStorageAccountName;
    }

    /**
     * (Updatable) Azure Storage Container Name.
     * 
     */
    @Import(name="azureStorageContainerName", required=true)
    private Output<String> azureStorageContainerName;

    /**
     * @return (Updatable) Azure Storage Container Name.
     * 
     */
    public Output<String> azureStorageContainerName() {
        return this.azureStorageContainerName;
    }

    /**
     * (Updatable) The OCID of the compartment that contains Oracle DB Azure Blob Container Resource.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment that contains Oracle DB Azure Blob Container Resource.
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
     * (Updatable) Display name of Oracle DB Azure Blob Container.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) Display name of Oracle DB Azure Blob Container.
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
     * (Updatable) Private endpoint DNS Alias.
     * 
     */
    @Import(name="privateEndpointDnsAlias")
    private @Nullable Output<String> privateEndpointDnsAlias;

    /**
     * @return (Updatable) Private endpoint DNS Alias.
     * 
     */
    public Optional<Output<String>> privateEndpointDnsAlias() {
        return Optional.ofNullable(this.privateEndpointDnsAlias);
    }

    /**
     * (Updatable) Private endpoint IP.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="privateEndpointIpAddress")
    private @Nullable Output<String> privateEndpointIpAddress;

    /**
     * @return (Updatable) Private endpoint IP.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> privateEndpointIpAddress() {
        return Optional.ofNullable(this.privateEndpointIpAddress);
    }

    private DbmulticloudOracleDbAzureBlobContainerArgs() {}

    private DbmulticloudOracleDbAzureBlobContainerArgs(DbmulticloudOracleDbAzureBlobContainerArgs $) {
        this.azureStorageAccountName = $.azureStorageAccountName;
        this.azureStorageContainerName = $.azureStorageContainerName;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.privateEndpointDnsAlias = $.privateEndpointDnsAlias;
        this.privateEndpointIpAddress = $.privateEndpointIpAddress;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DbmulticloudOracleDbAzureBlobContainerArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DbmulticloudOracleDbAzureBlobContainerArgs $;

        public Builder() {
            $ = new DbmulticloudOracleDbAzureBlobContainerArgs();
        }

        public Builder(DbmulticloudOracleDbAzureBlobContainerArgs defaults) {
            $ = new DbmulticloudOracleDbAzureBlobContainerArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param azureStorageAccountName (Updatable) Azure Storage Account Name.
         * 
         * @return builder
         * 
         */
        public Builder azureStorageAccountName(Output<String> azureStorageAccountName) {
            $.azureStorageAccountName = azureStorageAccountName;
            return this;
        }

        /**
         * @param azureStorageAccountName (Updatable) Azure Storage Account Name.
         * 
         * @return builder
         * 
         */
        public Builder azureStorageAccountName(String azureStorageAccountName) {
            return azureStorageAccountName(Output.of(azureStorageAccountName));
        }

        /**
         * @param azureStorageContainerName (Updatable) Azure Storage Container Name.
         * 
         * @return builder
         * 
         */
        public Builder azureStorageContainerName(Output<String> azureStorageContainerName) {
            $.azureStorageContainerName = azureStorageContainerName;
            return this;
        }

        /**
         * @param azureStorageContainerName (Updatable) Azure Storage Container Name.
         * 
         * @return builder
         * 
         */
        public Builder azureStorageContainerName(String azureStorageContainerName) {
            return azureStorageContainerName(Output.of(azureStorageContainerName));
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment that contains Oracle DB Azure Blob Container Resource.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment that contains Oracle DB Azure Blob Container Resource.
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
         * @param displayName (Updatable) Display name of Oracle DB Azure Blob Container.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Display name of Oracle DB Azure Blob Container.
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
         * @param privateEndpointDnsAlias (Updatable) Private endpoint DNS Alias.
         * 
         * @return builder
         * 
         */
        public Builder privateEndpointDnsAlias(@Nullable Output<String> privateEndpointDnsAlias) {
            $.privateEndpointDnsAlias = privateEndpointDnsAlias;
            return this;
        }

        /**
         * @param privateEndpointDnsAlias (Updatable) Private endpoint DNS Alias.
         * 
         * @return builder
         * 
         */
        public Builder privateEndpointDnsAlias(String privateEndpointDnsAlias) {
            return privateEndpointDnsAlias(Output.of(privateEndpointDnsAlias));
        }

        /**
         * @param privateEndpointIpAddress (Updatable) Private endpoint IP.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder privateEndpointIpAddress(@Nullable Output<String> privateEndpointIpAddress) {
            $.privateEndpointIpAddress = privateEndpointIpAddress;
            return this;
        }

        /**
         * @param privateEndpointIpAddress (Updatable) Private endpoint IP.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder privateEndpointIpAddress(String privateEndpointIpAddress) {
            return privateEndpointIpAddress(Output.of(privateEndpointIpAddress));
        }

        public DbmulticloudOracleDbAzureBlobContainerArgs build() {
            if ($.azureStorageAccountName == null) {
                throw new MissingRequiredPropertyException("DbmulticloudOracleDbAzureBlobContainerArgs", "azureStorageAccountName");
            }
            if ($.azureStorageContainerName == null) {
                throw new MissingRequiredPropertyException("DbmulticloudOracleDbAzureBlobContainerArgs", "azureStorageContainerName");
            }
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("DbmulticloudOracleDbAzureBlobContainerArgs", "compartmentId");
            }
            if ($.displayName == null) {
                throw new MissingRequiredPropertyException("DbmulticloudOracleDbAzureBlobContainerArgs", "displayName");
            }
            return $;
        }
    }

}
