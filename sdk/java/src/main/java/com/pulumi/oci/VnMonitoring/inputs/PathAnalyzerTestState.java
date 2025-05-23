// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.VnMonitoring.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.VnMonitoring.inputs.PathAnalyzerTestDestinationEndpointArgs;
import com.pulumi.oci.VnMonitoring.inputs.PathAnalyzerTestProtocolParametersArgs;
import com.pulumi.oci.VnMonitoring.inputs.PathAnalyzerTestQueryOptionsArgs;
import com.pulumi.oci.VnMonitoring.inputs.PathAnalyzerTestSourceEndpointArgs;
import java.lang.Integer;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class PathAnalyzerTestState extends com.pulumi.resources.ResourceArgs {

    public static final PathAnalyzerTestState Empty = new PathAnalyzerTestState();

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the `PathAnalyzerTest` resource&#39;s compartment.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the `PathAnalyzerTest` resource&#39;s compartment.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) Information describing a source or destination in a `PathAnalyzerTest` resource.
     * 
     */
    @Import(name="destinationEndpoint")
    private @Nullable Output<PathAnalyzerTestDestinationEndpointArgs> destinationEndpoint;

    /**
     * @return (Updatable) Information describing a source or destination in a `PathAnalyzerTest` resource.
     * 
     */
    public Optional<Output<PathAnalyzerTestDestinationEndpointArgs>> destinationEndpoint() {
        return Optional.ofNullable(this.destinationEndpoint);
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
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) The IP protocol to use in the `PathAnalyzerTest` resource.
     * 
     */
    @Import(name="protocol")
    private @Nullable Output<Integer> protocol;

    /**
     * @return (Updatable) The IP protocol to use in the `PathAnalyzerTest` resource.
     * 
     */
    public Optional<Output<Integer>> protocol() {
        return Optional.ofNullable(this.protocol);
    }

    /**
     * (Updatable) Defines the IP protocol parameters for a `PathAnalyzerTest` resource.
     * 
     */
    @Import(name="protocolParameters")
    private @Nullable Output<PathAnalyzerTestProtocolParametersArgs> protocolParameters;

    /**
     * @return (Updatable) Defines the IP protocol parameters for a `PathAnalyzerTest` resource.
     * 
     */
    public Optional<Output<PathAnalyzerTestProtocolParametersArgs>> protocolParameters() {
        return Optional.ofNullable(this.protocolParameters);
    }

    /**
     * (Updatable) Defines the query options required for a `PathAnalyzerTest` resource.
     * 
     */
    @Import(name="queryOptions")
    private @Nullable Output<PathAnalyzerTestQueryOptionsArgs> queryOptions;

    /**
     * @return (Updatable) Defines the query options required for a `PathAnalyzerTest` resource.
     * 
     */
    public Optional<Output<PathAnalyzerTestQueryOptionsArgs>> queryOptions() {
        return Optional.ofNullable(this.queryOptions);
    }

    /**
     * (Updatable) Information describing a source or destination in a `PathAnalyzerTest` resource.
     * 
     */
    @Import(name="sourceEndpoint")
    private @Nullable Output<PathAnalyzerTestSourceEndpointArgs> sourceEndpoint;

    /**
     * @return (Updatable) Information describing a source or destination in a `PathAnalyzerTest` resource.
     * 
     */
    public Optional<Output<PathAnalyzerTestSourceEndpointArgs>> sourceEndpoint() {
        return Optional.ofNullable(this.sourceEndpoint);
    }

    /**
     * The current state of the `PathAnalyzerTest` resource.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the `PathAnalyzerTest` resource.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Import(name="systemTags")
    private @Nullable Output<Map<String,String>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> systemTags() {
        return Optional.ofNullable(this.systemTags);
    }

    /**
     * The date and time the `PathAnalyzerTest` resource was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the `PathAnalyzerTest` resource was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The date and time the `PathAnalyzerTest` resource was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The date and time the `PathAnalyzerTest` resource was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    private PathAnalyzerTestState() {}

    private PathAnalyzerTestState(PathAnalyzerTestState $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.destinationEndpoint = $.destinationEndpoint;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.protocol = $.protocol;
        this.protocolParameters = $.protocolParameters;
        this.queryOptions = $.queryOptions;
        this.sourceEndpoint = $.sourceEndpoint;
        this.state = $.state;
        this.systemTags = $.systemTags;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(PathAnalyzerTestState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private PathAnalyzerTestState $;

        public Builder() {
            $ = new PathAnalyzerTestState();
        }

        public Builder(PathAnalyzerTestState defaults) {
            $ = new PathAnalyzerTestState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the `PathAnalyzerTest` resource&#39;s compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the `PathAnalyzerTest` resource&#39;s compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param destinationEndpoint (Updatable) Information describing a source or destination in a `PathAnalyzerTest` resource.
         * 
         * @return builder
         * 
         */
        public Builder destinationEndpoint(@Nullable Output<PathAnalyzerTestDestinationEndpointArgs> destinationEndpoint) {
            $.destinationEndpoint = destinationEndpoint;
            return this;
        }

        /**
         * @param destinationEndpoint (Updatable) Information describing a source or destination in a `PathAnalyzerTest` resource.
         * 
         * @return builder
         * 
         */
        public Builder destinationEndpoint(PathAnalyzerTestDestinationEndpointArgs destinationEndpoint) {
            return destinationEndpoint(Output.of(destinationEndpoint));
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
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param protocol (Updatable) The IP protocol to use in the `PathAnalyzerTest` resource.
         * 
         * @return builder
         * 
         */
        public Builder protocol(@Nullable Output<Integer> protocol) {
            $.protocol = protocol;
            return this;
        }

        /**
         * @param protocol (Updatable) The IP protocol to use in the `PathAnalyzerTest` resource.
         * 
         * @return builder
         * 
         */
        public Builder protocol(Integer protocol) {
            return protocol(Output.of(protocol));
        }

        /**
         * @param protocolParameters (Updatable) Defines the IP protocol parameters for a `PathAnalyzerTest` resource.
         * 
         * @return builder
         * 
         */
        public Builder protocolParameters(@Nullable Output<PathAnalyzerTestProtocolParametersArgs> protocolParameters) {
            $.protocolParameters = protocolParameters;
            return this;
        }

        /**
         * @param protocolParameters (Updatable) Defines the IP protocol parameters for a `PathAnalyzerTest` resource.
         * 
         * @return builder
         * 
         */
        public Builder protocolParameters(PathAnalyzerTestProtocolParametersArgs protocolParameters) {
            return protocolParameters(Output.of(protocolParameters));
        }

        /**
         * @param queryOptions (Updatable) Defines the query options required for a `PathAnalyzerTest` resource.
         * 
         * @return builder
         * 
         */
        public Builder queryOptions(@Nullable Output<PathAnalyzerTestQueryOptionsArgs> queryOptions) {
            $.queryOptions = queryOptions;
            return this;
        }

        /**
         * @param queryOptions (Updatable) Defines the query options required for a `PathAnalyzerTest` resource.
         * 
         * @return builder
         * 
         */
        public Builder queryOptions(PathAnalyzerTestQueryOptionsArgs queryOptions) {
            return queryOptions(Output.of(queryOptions));
        }

        /**
         * @param sourceEndpoint (Updatable) Information describing a source or destination in a `PathAnalyzerTest` resource.
         * 
         * @return builder
         * 
         */
        public Builder sourceEndpoint(@Nullable Output<PathAnalyzerTestSourceEndpointArgs> sourceEndpoint) {
            $.sourceEndpoint = sourceEndpoint;
            return this;
        }

        /**
         * @param sourceEndpoint (Updatable) Information describing a source or destination in a `PathAnalyzerTest` resource.
         * 
         * @return builder
         * 
         */
        public Builder sourceEndpoint(PathAnalyzerTestSourceEndpointArgs sourceEndpoint) {
            return sourceEndpoint(Output.of(sourceEndpoint));
        }

        /**
         * @param state The current state of the `PathAnalyzerTest` resource.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the `PathAnalyzerTest` resource.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param systemTags Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(@Nullable Output<Map<String,String>> systemTags) {
            $.systemTags = systemTags;
            return this;
        }

        /**
         * @param systemTags Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(Map<String,String> systemTags) {
            return systemTags(Output.of(systemTags));
        }

        /**
         * @param timeCreated The date and time the `PathAnalyzerTest` resource was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the `PathAnalyzerTest` resource was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The date and time the `PathAnalyzerTest` resource was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The date and time the `PathAnalyzerTest` resource was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        public PathAnalyzerTestState build() {
            return $;
        }
    }

}
