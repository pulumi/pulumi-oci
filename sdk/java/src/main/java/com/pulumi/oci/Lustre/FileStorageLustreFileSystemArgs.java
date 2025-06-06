// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Lustre;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Lustre.inputs.FileStorageLustreFileSystemRootSquashConfigurationArgs;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class FileStorageLustreFileSystemArgs extends com.pulumi.resources.ResourceArgs {

    public static final FileStorageLustreFileSystemArgs Empty = new FileStorageLustreFileSystemArgs();

    /**
     * The availability domain the file system is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
     * 
     */
    @Import(name="availabilityDomain", required=true)
    private Output<String> availabilityDomain;

    /**
     * @return The availability domain the file system is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public Output<String> availabilityDomain() {
        return this.availabilityDomain;
    }

    /**
     * (Updatable) Capacity of the Lustre file system in GB. You can increase capacity only in multiples of 5 TB.
     * 
     */
    @Import(name="capacityInGbs", required=true)
    private Output<Integer> capacityInGbs;

    /**
     * @return (Updatable) Capacity of the Lustre file system in GB. You can increase capacity only in multiples of 5 TB.
     * 
     */
    public Output<Integer> capacityInGbs() {
        return this.capacityInGbs;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cluster placement group in which the Lustre file system exists.
     * 
     */
    @Import(name="clusterPlacementGroupId")
    private @Nullable Output<String> clusterPlacementGroupId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cluster placement group in which the Lustre file system exists.
     * 
     */
    public Optional<Output<String>> clusterPlacementGroupId() {
        return Optional.ofNullable(this.clusterPlacementGroupId);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the Lustre file system.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the Lustre file system.
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
     * (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My Lustre file system`
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My Lustre file system`
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) Short description of the Lustre file system. Avoid entering confidential information.
     * 
     */
    @Import(name="fileSystemDescription")
    private @Nullable Output<String> fileSystemDescription;

    /**
     * @return (Updatable) Short description of the Lustre file system. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> fileSystemDescription() {
        return Optional.ofNullable(this.fileSystemDescription);
    }

    /**
     * The Lustre file system name. This is used in mount commands and other aspects of the client command line interface. The file system name is limited to 8 characters. Allowed characters are lower and upper case English letters, numbers, and &#39;_&#39;. If you have multiple Lustre file systems mounted on the same clients, this name can help distinguish them.
     * 
     */
    @Import(name="fileSystemName", required=true)
    private Output<String> fileSystemName;

    /**
     * @return The Lustre file system name. This is used in mount commands and other aspects of the client command line interface. The file system name is limited to 8 characters. Allowed characters are lower and upper case English letters, numbers, and &#39;_&#39;. If you have multiple Lustre file systems mounted on the same clients, this name can help distinguish them.
     * 
     */
    public Output<String> fileSystemName() {
        return this.fileSystemName;
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
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the KMS key used to encrypt the encryption keys associated with this file system.
     * 
     */
    @Import(name="kmsKeyId")
    private @Nullable Output<String> kmsKeyId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the KMS key used to encrypt the encryption keys associated with this file system.
     * 
     */
    public Optional<Output<String>> kmsKeyId() {
        return Optional.ofNullable(this.kmsKeyId);
    }

    /**
     * (Updatable) A list of Network Security Group [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with this lustre file system. A maximum of 5 is allowed. Setting this to an empty array after the list is created removes the lustre file system from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm).
     * 
     */
    @Import(name="nsgIds")
    private @Nullable Output<List<String>> nsgIds;

    /**
     * @return (Updatable) A list of Network Security Group [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with this lustre file system. A maximum of 5 is allowed. Setting this to an empty array after the list is created removes the lustre file system from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm).
     * 
     */
    public Optional<Output<List<String>>> nsgIds() {
        return Optional.ofNullable(this.nsgIds);
    }

    /**
     * The Lustre file system performance tier. A value of `MBPS_PER_TB_125` represents 125 megabytes per second per terabyte.
     * 
     */
    @Import(name="performanceTier", required=true)
    private Output<String> performanceTier;

    /**
     * @return The Lustre file system performance tier. A value of `MBPS_PER_TB_125` represents 125 megabytes per second per terabyte.
     * 
     */
    public Output<String> performanceTier() {
        return this.performanceTier;
    }

    /**
     * (Updatable) An administrative feature that allows you to restrict root level access from clients that try to access your Lustre file system as root.
     * 
     */
    @Import(name="rootSquashConfiguration", required=true)
    private Output<FileStorageLustreFileSystemRootSquashConfigurationArgs> rootSquashConfiguration;

    /**
     * @return (Updatable) An administrative feature that allows you to restrict root level access from clients that try to access your Lustre file system as root.
     * 
     */
    public Output<FileStorageLustreFileSystemRootSquashConfigurationArgs> rootSquashConfiguration() {
        return this.rootSquashConfiguration;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet the Lustre file system is in.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="subnetId", required=true)
    private Output<String> subnetId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet the Lustre file system is in.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> subnetId() {
        return this.subnetId;
    }

    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Import(name="systemTags")
    private @Nullable Output<Map<String,String>> systemTags;

    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> systemTags() {
        return Optional.ofNullable(this.systemTags);
    }

    private FileStorageLustreFileSystemArgs() {}

    private FileStorageLustreFileSystemArgs(FileStorageLustreFileSystemArgs $) {
        this.availabilityDomain = $.availabilityDomain;
        this.capacityInGbs = $.capacityInGbs;
        this.clusterPlacementGroupId = $.clusterPlacementGroupId;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.fileSystemDescription = $.fileSystemDescription;
        this.fileSystemName = $.fileSystemName;
        this.freeformTags = $.freeformTags;
        this.kmsKeyId = $.kmsKeyId;
        this.nsgIds = $.nsgIds;
        this.performanceTier = $.performanceTier;
        this.rootSquashConfiguration = $.rootSquashConfiguration;
        this.subnetId = $.subnetId;
        this.systemTags = $.systemTags;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(FileStorageLustreFileSystemArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private FileStorageLustreFileSystemArgs $;

        public Builder() {
            $ = new FileStorageLustreFileSystemArgs();
        }

        public Builder(FileStorageLustreFileSystemArgs defaults) {
            $ = new FileStorageLustreFileSystemArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param availabilityDomain The availability domain the file system is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(Output<String> availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param availabilityDomain The availability domain the file system is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(String availabilityDomain) {
            return availabilityDomain(Output.of(availabilityDomain));
        }

        /**
         * @param capacityInGbs (Updatable) Capacity of the Lustre file system in GB. You can increase capacity only in multiples of 5 TB.
         * 
         * @return builder
         * 
         */
        public Builder capacityInGbs(Output<Integer> capacityInGbs) {
            $.capacityInGbs = capacityInGbs;
            return this;
        }

        /**
         * @param capacityInGbs (Updatable) Capacity of the Lustre file system in GB. You can increase capacity only in multiples of 5 TB.
         * 
         * @return builder
         * 
         */
        public Builder capacityInGbs(Integer capacityInGbs) {
            return capacityInGbs(Output.of(capacityInGbs));
        }

        /**
         * @param clusterPlacementGroupId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cluster placement group in which the Lustre file system exists.
         * 
         * @return builder
         * 
         */
        public Builder clusterPlacementGroupId(@Nullable Output<String> clusterPlacementGroupId) {
            $.clusterPlacementGroupId = clusterPlacementGroupId;
            return this;
        }

        /**
         * @param clusterPlacementGroupId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cluster placement group in which the Lustre file system exists.
         * 
         * @return builder
         * 
         */
        public Builder clusterPlacementGroupId(String clusterPlacementGroupId) {
            return clusterPlacementGroupId(Output.of(clusterPlacementGroupId));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the Lustre file system.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the Lustre file system.
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
         * @param displayName (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My Lustre file system`
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My Lustre file system`
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param fileSystemDescription (Updatable) Short description of the Lustre file system. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder fileSystemDescription(@Nullable Output<String> fileSystemDescription) {
            $.fileSystemDescription = fileSystemDescription;
            return this;
        }

        /**
         * @param fileSystemDescription (Updatable) Short description of the Lustre file system. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder fileSystemDescription(String fileSystemDescription) {
            return fileSystemDescription(Output.of(fileSystemDescription));
        }

        /**
         * @param fileSystemName The Lustre file system name. This is used in mount commands and other aspects of the client command line interface. The file system name is limited to 8 characters. Allowed characters are lower and upper case English letters, numbers, and &#39;_&#39;. If you have multiple Lustre file systems mounted on the same clients, this name can help distinguish them.
         * 
         * @return builder
         * 
         */
        public Builder fileSystemName(Output<String> fileSystemName) {
            $.fileSystemName = fileSystemName;
            return this;
        }

        /**
         * @param fileSystemName The Lustre file system name. This is used in mount commands and other aspects of the client command line interface. The file system name is limited to 8 characters. Allowed characters are lower and upper case English letters, numbers, and &#39;_&#39;. If you have multiple Lustre file systems mounted on the same clients, this name can help distinguish them.
         * 
         * @return builder
         * 
         */
        public Builder fileSystemName(String fileSystemName) {
            return fileSystemName(Output.of(fileSystemName));
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
         * @param kmsKeyId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the KMS key used to encrypt the encryption keys associated with this file system.
         * 
         * @return builder
         * 
         */
        public Builder kmsKeyId(@Nullable Output<String> kmsKeyId) {
            $.kmsKeyId = kmsKeyId;
            return this;
        }

        /**
         * @param kmsKeyId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the KMS key used to encrypt the encryption keys associated with this file system.
         * 
         * @return builder
         * 
         */
        public Builder kmsKeyId(String kmsKeyId) {
            return kmsKeyId(Output.of(kmsKeyId));
        }

        /**
         * @param nsgIds (Updatable) A list of Network Security Group [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with this lustre file system. A maximum of 5 is allowed. Setting this to an empty array after the list is created removes the lustre file system from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm).
         * 
         * @return builder
         * 
         */
        public Builder nsgIds(@Nullable Output<List<String>> nsgIds) {
            $.nsgIds = nsgIds;
            return this;
        }

        /**
         * @param nsgIds (Updatable) A list of Network Security Group [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with this lustre file system. A maximum of 5 is allowed. Setting this to an empty array after the list is created removes the lustre file system from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm).
         * 
         * @return builder
         * 
         */
        public Builder nsgIds(List<String> nsgIds) {
            return nsgIds(Output.of(nsgIds));
        }

        /**
         * @param nsgIds (Updatable) A list of Network Security Group [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with this lustre file system. A maximum of 5 is allowed. Setting this to an empty array after the list is created removes the lustre file system from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm).
         * 
         * @return builder
         * 
         */
        public Builder nsgIds(String... nsgIds) {
            return nsgIds(List.of(nsgIds));
        }

        /**
         * @param performanceTier The Lustre file system performance tier. A value of `MBPS_PER_TB_125` represents 125 megabytes per second per terabyte.
         * 
         * @return builder
         * 
         */
        public Builder performanceTier(Output<String> performanceTier) {
            $.performanceTier = performanceTier;
            return this;
        }

        /**
         * @param performanceTier The Lustre file system performance tier. A value of `MBPS_PER_TB_125` represents 125 megabytes per second per terabyte.
         * 
         * @return builder
         * 
         */
        public Builder performanceTier(String performanceTier) {
            return performanceTier(Output.of(performanceTier));
        }

        /**
         * @param rootSquashConfiguration (Updatable) An administrative feature that allows you to restrict root level access from clients that try to access your Lustre file system as root.
         * 
         * @return builder
         * 
         */
        public Builder rootSquashConfiguration(Output<FileStorageLustreFileSystemRootSquashConfigurationArgs> rootSquashConfiguration) {
            $.rootSquashConfiguration = rootSquashConfiguration;
            return this;
        }

        /**
         * @param rootSquashConfiguration (Updatable) An administrative feature that allows you to restrict root level access from clients that try to access your Lustre file system as root.
         * 
         * @return builder
         * 
         */
        public Builder rootSquashConfiguration(FileStorageLustreFileSystemRootSquashConfigurationArgs rootSquashConfiguration) {
            return rootSquashConfiguration(Output.of(rootSquashConfiguration));
        }

        /**
         * @param subnetId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet the Lustre file system is in.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder subnetId(Output<String> subnetId) {
            $.subnetId = subnetId;
            return this;
        }

        /**
         * @param subnetId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet the Lustre file system is in.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder subnetId(String subnetId) {
            return subnetId(Output.of(subnetId));
        }

        /**
         * @param systemTags System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(@Nullable Output<Map<String,String>> systemTags) {
            $.systemTags = systemTags;
            return this;
        }

        /**
         * @param systemTags System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(Map<String,String> systemTags) {
            return systemTags(Output.of(systemTags));
        }

        public FileStorageLustreFileSystemArgs build() {
            if ($.availabilityDomain == null) {
                throw new MissingRequiredPropertyException("FileStorageLustreFileSystemArgs", "availabilityDomain");
            }
            if ($.capacityInGbs == null) {
                throw new MissingRequiredPropertyException("FileStorageLustreFileSystemArgs", "capacityInGbs");
            }
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("FileStorageLustreFileSystemArgs", "compartmentId");
            }
            if ($.fileSystemName == null) {
                throw new MissingRequiredPropertyException("FileStorageLustreFileSystemArgs", "fileSystemName");
            }
            if ($.performanceTier == null) {
                throw new MissingRequiredPropertyException("FileStorageLustreFileSystemArgs", "performanceTier");
            }
            if ($.rootSquashConfiguration == null) {
                throw new MissingRequiredPropertyException("FileStorageLustreFileSystemArgs", "rootSquashConfiguration");
            }
            if ($.subnetId == null) {
                throw new MissingRequiredPropertyException("FileStorageLustreFileSystemArgs", "subnetId");
            }
            return $;
        }
    }

}
