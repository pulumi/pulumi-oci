// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.OsManagementHub.inputs.ManagementStationMirrorArgs;
import com.pulumi.oci.OsManagementHub.inputs.ManagementStationProxyArgs;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ManagementStationArgs extends com.pulumi.resources.ResourceArgs {

    public static final ManagementStationArgs Empty = new ManagementStationArgs();

    /**
     * The OCID of the tenancy containing the Management Station.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The OCID of the tenancy containing the Management Station.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) Details describing the Management Station config.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) Details describing the Management Station config.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) Management Station name
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) Management Station name
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) Name of the host
     * 
     */
    @Import(name="hostname", required=true)
    private Output<String> hostname;

    /**
     * @return (Updatable) Name of the host
     * 
     */
    public Output<String> hostname() {
        return this.hostname;
    }

    /**
     * (Updatable) Information for creating a mirror configuration
     * 
     */
    @Import(name="mirror", required=true)
    private Output<ManagementStationMirrorArgs> mirror;

    /**
     * @return (Updatable) Information for creating a mirror configuration
     * 
     */
    public Output<ManagementStationMirrorArgs> mirror() {
        return this.mirror;
    }

    /**
     * (Updatable) Information for creating a proxy configuration
     * 
     */
    @Import(name="proxy", required=true)
    private Output<ManagementStationProxyArgs> proxy;

    /**
     * @return (Updatable) Information for creating a proxy configuration
     * 
     */
    public Output<ManagementStationProxyArgs> proxy() {
        return this.proxy;
    }

    private ManagementStationArgs() {}

    private ManagementStationArgs(ManagementStationArgs $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.hostname = $.hostname;
        this.mirror = $.mirror;
        this.proxy = $.proxy;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ManagementStationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ManagementStationArgs $;

        public Builder() {
            $ = new ManagementStationArgs();
        }

        public Builder(ManagementStationArgs defaults) {
            $ = new ManagementStationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the tenancy containing the Management Station.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the tenancy containing the Management Station.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) Details describing the Management Station config.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) Details describing the Management Station config.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) Management Station name
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Management Station name
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
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param hostname (Updatable) Name of the host
         * 
         * @return builder
         * 
         */
        public Builder hostname(Output<String> hostname) {
            $.hostname = hostname;
            return this;
        }

        /**
         * @param hostname (Updatable) Name of the host
         * 
         * @return builder
         * 
         */
        public Builder hostname(String hostname) {
            return hostname(Output.of(hostname));
        }

        /**
         * @param mirror (Updatable) Information for creating a mirror configuration
         * 
         * @return builder
         * 
         */
        public Builder mirror(Output<ManagementStationMirrorArgs> mirror) {
            $.mirror = mirror;
            return this;
        }

        /**
         * @param mirror (Updatable) Information for creating a mirror configuration
         * 
         * @return builder
         * 
         */
        public Builder mirror(ManagementStationMirrorArgs mirror) {
            return mirror(Output.of(mirror));
        }

        /**
         * @param proxy (Updatable) Information for creating a proxy configuration
         * 
         * @return builder
         * 
         */
        public Builder proxy(Output<ManagementStationProxyArgs> proxy) {
            $.proxy = proxy;
            return this;
        }

        /**
         * @param proxy (Updatable) Information for creating a proxy configuration
         * 
         * @return builder
         * 
         */
        public Builder proxy(ManagementStationProxyArgs proxy) {
            return proxy(Output.of(proxy));
        }

        public ManagementStationArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.displayName = Objects.requireNonNull($.displayName, "expected parameter 'displayName' to be non-null");
            $.hostname = Objects.requireNonNull($.hostname, "expected parameter 'hostname' to be non-null");
            $.mirror = Objects.requireNonNull($.mirror, "expected parameter 'mirror' to be non-null");
            $.proxy = Objects.requireNonNull($.proxy, "expected parameter 'proxy' to be non-null");
            return $;
        }
    }

}