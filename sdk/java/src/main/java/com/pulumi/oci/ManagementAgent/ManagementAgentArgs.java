// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ManagementAgent;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ManagementAgentArgs extends com.pulumi.resources.ResourceArgs {

    public static final ManagementAgentArgs Empty = new ManagementAgentArgs();

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    @Import(name="deployPluginsIds")
    private @Nullable Output<List<String>> deployPluginsIds;

    public Optional<Output<List<String>>> deployPluginsIds() {
        return Optional.ofNullable(this.deployPluginsIds);
    }

    /**
     * (Updatable) New displayName of Agent.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) New displayName of Agent.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * Unique Management Agent identifier
     * 
     */
    @Import(name="managedAgentId", required=true)
    private Output<String> managedAgentId;

    /**
     * @return Unique Management Agent identifier
     * 
     */
    public Output<String> managedAgentId() {
        return this.managedAgentId;
    }

    private ManagementAgentArgs() {}

    private ManagementAgentArgs(ManagementAgentArgs $) {
        this.definedTags = $.definedTags;
        this.deployPluginsIds = $.deployPluginsIds;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.managedAgentId = $.managedAgentId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ManagementAgentArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ManagementAgentArgs $;

        public Builder() {
            $ = new ManagementAgentArgs();
        }

        public Builder(ManagementAgentArgs defaults) {
            $ = new ManagementAgentArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        public Builder deployPluginsIds(@Nullable Output<List<String>> deployPluginsIds) {
            $.deployPluginsIds = deployPluginsIds;
            return this;
        }

        public Builder deployPluginsIds(List<String> deployPluginsIds) {
            return deployPluginsIds(Output.of(deployPluginsIds));
        }

        public Builder deployPluginsIds(String... deployPluginsIds) {
            return deployPluginsIds(List.of(deployPluginsIds));
        }

        /**
         * @param displayName (Updatable) New displayName of Agent.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) New displayName of Agent.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param managedAgentId Unique Management Agent identifier
         * 
         * @return builder
         * 
         */
        public Builder managedAgentId(Output<String> managedAgentId) {
            $.managedAgentId = managedAgentId;
            return this;
        }

        /**
         * @param managedAgentId Unique Management Agent identifier
         * 
         * @return builder
         * 
         */
        public Builder managedAgentId(String managedAgentId) {
            return managedAgentId(Output.of(managedAgentId));
        }

        public ManagementAgentArgs build() {
            if ($.managedAgentId == null) {
                throw new MissingRequiredPropertyException("ManagementAgentArgs", "managedAgentId");
            }
            return $;
        }
    }

}
