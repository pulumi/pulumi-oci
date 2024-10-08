// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.inputs.CrossConnectGroupMacsecPropertiesArgs;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class CrossConnectGroupArgs extends com.pulumi.resources.ResourceArgs {

    public static final CrossConnectGroupArgs Empty = new CrossConnectGroupArgs();

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the cross-connect group.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the cross-connect group.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) A reference name or identifier for the physical fiber connection that this cross-connect group uses.
     * 
     */
    @Import(name="customerReferenceName")
    private @Nullable Output<String> customerReferenceName;

    /**
     * @return (Updatable) A reference name or identifier for the physical fiber connection that this cross-connect group uses.
     * 
     */
    public Optional<Output<String>> customerReferenceName() {
        return Optional.ofNullable(this.customerReferenceName);
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
     * (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
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
     * (Updatable) Properties used to configure MACsec (if capable).
     * 
     */
    @Import(name="macsecProperties")
    private @Nullable Output<CrossConnectGroupMacsecPropertiesArgs> macsecProperties;

    /**
     * @return (Updatable) Properties used to configure MACsec (if capable).
     * 
     */
    public Optional<Output<CrossConnectGroupMacsecPropertiesArgs>> macsecProperties() {
        return Optional.ofNullable(this.macsecProperties);
    }

    private CrossConnectGroupArgs() {}

    private CrossConnectGroupArgs(CrossConnectGroupArgs $) {
        this.compartmentId = $.compartmentId;
        this.customerReferenceName = $.customerReferenceName;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.macsecProperties = $.macsecProperties;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(CrossConnectGroupArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private CrossConnectGroupArgs $;

        public Builder() {
            $ = new CrossConnectGroupArgs();
        }

        public Builder(CrossConnectGroupArgs defaults) {
            $ = new CrossConnectGroupArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the cross-connect group.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the cross-connect group.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param customerReferenceName (Updatable) A reference name or identifier for the physical fiber connection that this cross-connect group uses.
         * 
         * @return builder
         * 
         */
        public Builder customerReferenceName(@Nullable Output<String> customerReferenceName) {
            $.customerReferenceName = customerReferenceName;
            return this;
        }

        /**
         * @param customerReferenceName (Updatable) A reference name or identifier for the physical fiber connection that this cross-connect group uses.
         * 
         * @return builder
         * 
         */
        public Builder customerReferenceName(String customerReferenceName) {
            return customerReferenceName(Output.of(customerReferenceName));
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
         * @param displayName (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
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
         * @param macsecProperties (Updatable) Properties used to configure MACsec (if capable).
         * 
         * @return builder
         * 
         */
        public Builder macsecProperties(@Nullable Output<CrossConnectGroupMacsecPropertiesArgs> macsecProperties) {
            $.macsecProperties = macsecProperties;
            return this;
        }

        /**
         * @param macsecProperties (Updatable) Properties used to configure MACsec (if capable).
         * 
         * @return builder
         * 
         */
        public Builder macsecProperties(CrossConnectGroupMacsecPropertiesArgs macsecProperties) {
            return macsecProperties(Output.of(macsecProperties));
        }

        public CrossConnectGroupArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("CrossConnectGroupArgs", "compartmentId");
            }
            return $;
        }
    }

}
