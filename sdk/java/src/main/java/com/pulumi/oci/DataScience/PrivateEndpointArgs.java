// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class PrivateEndpointArgs extends com.pulumi.resources.ResourceArgs {

    public static final PrivateEndpointArgs Empty = new PrivateEndpointArgs();

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the private endpoint.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the private endpoint.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * Data Science resource type.
     * 
     */
    @Import(name="dataScienceResourceType", required=true)
    private Output<String> dataScienceResourceType;

    /**
     * @return Data Science resource type.
     * 
     */
    public Output<String> dataScienceResourceType() {
        return this.dataScienceResourceType;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) A user friendly description. Avoid entering confidential information.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) A user friendly description. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) A user friendly name. It doesn&#39;t have to be unique. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) A user friendly name. It doesn&#39;t have to be unique. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) An array of network security group OCIDs.
     * 
     */
    @Import(name="nsgIds")
    private @Nullable Output<List<String>> nsgIds;

    /**
     * @return (Updatable) An array of network security group OCIDs.
     * 
     */
    public Optional<Output<List<String>>> nsgIds() {
        return Optional.ofNullable(this.nsgIds);
    }

    /**
     * Subdomain for a private endpoint FQDN.
     * 
     */
    @Import(name="subDomain")
    private @Nullable Output<String> subDomain;

    /**
     * @return Subdomain for a private endpoint FQDN.
     * 
     */
    public Optional<Output<String>> subDomain() {
        return Optional.ofNullable(this.subDomain);
    }

    /**
     * The OCID of the subnet.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="subnetId", required=true)
    private Output<String> subnetId;

    /**
     * @return The OCID of the subnet.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> subnetId() {
        return this.subnetId;
    }

    private PrivateEndpointArgs() {}

    private PrivateEndpointArgs(PrivateEndpointArgs $) {
        this.compartmentId = $.compartmentId;
        this.dataScienceResourceType = $.dataScienceResourceType;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.nsgIds = $.nsgIds;
        this.subDomain = $.subDomain;
        this.subnetId = $.subnetId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(PrivateEndpointArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private PrivateEndpointArgs $;

        public Builder() {
            $ = new PrivateEndpointArgs();
        }

        public Builder(PrivateEndpointArgs defaults) {
            $ = new PrivateEndpointArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the private endpoint.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the private endpoint.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param dataScienceResourceType Data Science resource type.
         * 
         * @return builder
         * 
         */
        public Builder dataScienceResourceType(Output<String> dataScienceResourceType) {
            $.dataScienceResourceType = dataScienceResourceType;
            return this;
        }

        /**
         * @param dataScienceResourceType Data Science resource type.
         * 
         * @return builder
         * 
         */
        public Builder dataScienceResourceType(String dataScienceResourceType) {
            return dataScienceResourceType(Output.of(dataScienceResourceType));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) A user friendly description. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) A user friendly description. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) A user friendly name. It doesn&#39;t have to be unique. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user friendly name. It doesn&#39;t have to be unique. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param nsgIds (Updatable) An array of network security group OCIDs.
         * 
         * @return builder
         * 
         */
        public Builder nsgIds(@Nullable Output<List<String>> nsgIds) {
            $.nsgIds = nsgIds;
            return this;
        }

        /**
         * @param nsgIds (Updatable) An array of network security group OCIDs.
         * 
         * @return builder
         * 
         */
        public Builder nsgIds(List<String> nsgIds) {
            return nsgIds(Output.of(nsgIds));
        }

        /**
         * @param nsgIds (Updatable) An array of network security group OCIDs.
         * 
         * @return builder
         * 
         */
        public Builder nsgIds(String... nsgIds) {
            return nsgIds(List.of(nsgIds));
        }

        /**
         * @param subDomain Subdomain for a private endpoint FQDN.
         * 
         * @return builder
         * 
         */
        public Builder subDomain(@Nullable Output<String> subDomain) {
            $.subDomain = subDomain;
            return this;
        }

        /**
         * @param subDomain Subdomain for a private endpoint FQDN.
         * 
         * @return builder
         * 
         */
        public Builder subDomain(String subDomain) {
            return subDomain(Output.of(subDomain));
        }

        /**
         * @param subnetId The OCID of the subnet.
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
         * @param subnetId The OCID of the subnet.
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

        public PrivateEndpointArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("PrivateEndpointArgs", "compartmentId");
            }
            if ($.dataScienceResourceType == null) {
                throw new MissingRequiredPropertyException("PrivateEndpointArgs", "dataScienceResourceType");
            }
            if ($.subnetId == null) {
                throw new MissingRequiredPropertyException("PrivateEndpointArgs", "subnetId");
            }
            return $;
        }
    }

}
