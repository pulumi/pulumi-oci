// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GoldenGate.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.GoldenGate.inputs.GetConnectionsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetConnectionsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetConnectionsArgs Empty = new GetConnectionsArgs();

    /**
     * Filters for compatible connections which can be, but currently not assigned to the deployment specified by its id.
     * 
     */
    @Import(name="assignableDeploymentId")
    private @Nullable Output<String> assignableDeploymentId;

    /**
     * @return Filters for compatible connections which can be, but currently not assigned to the deployment specified by its id.
     * 
     */
    public Optional<Output<String>> assignableDeploymentId() {
        return Optional.ofNullable(this.assignableDeploymentId);
    }

    /**
     * Filters for connections which can be assigned to the latest version of the specified deployment type.
     * 
     */
    @Import(name="assignableDeploymentType")
    private @Nullable Output<String> assignableDeploymentType;

    /**
     * @return Filters for connections which can be assigned to the latest version of the specified deployment type.
     * 
     */
    public Optional<Output<String>> assignableDeploymentType() {
        return Optional.ofNullable(this.assignableDeploymentType);
    }

    /**
     * The OCID of the deployment which for the connection must be assigned.
     * 
     */
    @Import(name="assignedDeploymentId")
    private @Nullable Output<String> assignedDeploymentId;

    /**
     * @return The OCID of the deployment which for the connection must be assigned.
     * 
     */
    public Optional<Output<String>> assignedDeploymentId() {
        return Optional.ofNullable(this.assignedDeploymentId);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * The array of connection types.
     * 
     */
    @Import(name="connectionTypes")
    private @Nullable Output<List<String>> connectionTypes;

    /**
     * @return The array of connection types.
     * 
     */
    public Optional<Output<List<String>>> connectionTypes() {
        return Optional.ofNullable(this.connectionTypes);
    }

    /**
     * A filter to return only the resources that match the entire &#39;displayName&#39; given.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return only the resources that match the entire &#39;displayName&#39; given.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetConnectionsFilterArgs>> filters;

    public Optional<Output<List<GetConnectionsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only connections having the &#39;lifecycleState&#39; given.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return A filter to return only connections having the &#39;lifecycleState&#39; given.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The array of technology types.
     * 
     */
    @Import(name="technologyTypes")
    private @Nullable Output<List<String>> technologyTypes;

    /**
     * @return The array of technology types.
     * 
     */
    public Optional<Output<List<String>>> technologyTypes() {
        return Optional.ofNullable(this.technologyTypes);
    }

    private GetConnectionsArgs() {}

    private GetConnectionsArgs(GetConnectionsArgs $) {
        this.assignableDeploymentId = $.assignableDeploymentId;
        this.assignableDeploymentType = $.assignableDeploymentType;
        this.assignedDeploymentId = $.assignedDeploymentId;
        this.compartmentId = $.compartmentId;
        this.connectionTypes = $.connectionTypes;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.state = $.state;
        this.technologyTypes = $.technologyTypes;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetConnectionsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetConnectionsArgs $;

        public Builder() {
            $ = new GetConnectionsArgs();
        }

        public Builder(GetConnectionsArgs defaults) {
            $ = new GetConnectionsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param assignableDeploymentId Filters for compatible connections which can be, but currently not assigned to the deployment specified by its id.
         * 
         * @return builder
         * 
         */
        public Builder assignableDeploymentId(@Nullable Output<String> assignableDeploymentId) {
            $.assignableDeploymentId = assignableDeploymentId;
            return this;
        }

        /**
         * @param assignableDeploymentId Filters for compatible connections which can be, but currently not assigned to the deployment specified by its id.
         * 
         * @return builder
         * 
         */
        public Builder assignableDeploymentId(String assignableDeploymentId) {
            return assignableDeploymentId(Output.of(assignableDeploymentId));
        }

        /**
         * @param assignableDeploymentType Filters for connections which can be assigned to the latest version of the specified deployment type.
         * 
         * @return builder
         * 
         */
        public Builder assignableDeploymentType(@Nullable Output<String> assignableDeploymentType) {
            $.assignableDeploymentType = assignableDeploymentType;
            return this;
        }

        /**
         * @param assignableDeploymentType Filters for connections which can be assigned to the latest version of the specified deployment type.
         * 
         * @return builder
         * 
         */
        public Builder assignableDeploymentType(String assignableDeploymentType) {
            return assignableDeploymentType(Output.of(assignableDeploymentType));
        }

        /**
         * @param assignedDeploymentId The OCID of the deployment which for the connection must be assigned.
         * 
         * @return builder
         * 
         */
        public Builder assignedDeploymentId(@Nullable Output<String> assignedDeploymentId) {
            $.assignedDeploymentId = assignedDeploymentId;
            return this;
        }

        /**
         * @param assignedDeploymentId The OCID of the deployment which for the connection must be assigned.
         * 
         * @return builder
         * 
         */
        public Builder assignedDeploymentId(String assignedDeploymentId) {
            return assignedDeploymentId(Output.of(assignedDeploymentId));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param connectionTypes The array of connection types.
         * 
         * @return builder
         * 
         */
        public Builder connectionTypes(@Nullable Output<List<String>> connectionTypes) {
            $.connectionTypes = connectionTypes;
            return this;
        }

        /**
         * @param connectionTypes The array of connection types.
         * 
         * @return builder
         * 
         */
        public Builder connectionTypes(List<String> connectionTypes) {
            return connectionTypes(Output.of(connectionTypes));
        }

        /**
         * @param connectionTypes The array of connection types.
         * 
         * @return builder
         * 
         */
        public Builder connectionTypes(String... connectionTypes) {
            return connectionTypes(List.of(connectionTypes));
        }

        /**
         * @param displayName A filter to return only the resources that match the entire &#39;displayName&#39; given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return only the resources that match the entire &#39;displayName&#39; given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetConnectionsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetConnectionsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetConnectionsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param state A filter to return only connections having the &#39;lifecycleState&#39; given.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state A filter to return only connections having the &#39;lifecycleState&#39; given.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param technologyTypes The array of technology types.
         * 
         * @return builder
         * 
         */
        public Builder technologyTypes(@Nullable Output<List<String>> technologyTypes) {
            $.technologyTypes = technologyTypes;
            return this;
        }

        /**
         * @param technologyTypes The array of technology types.
         * 
         * @return builder
         * 
         */
        public Builder technologyTypes(List<String> technologyTypes) {
            return technologyTypes(Output.of(technologyTypes));
        }

        /**
         * @param technologyTypes The array of technology types.
         * 
         * @return builder
         * 
         */
        public Builder technologyTypes(String... technologyTypes) {
            return technologyTypes(List.of(technologyTypes));
        }

        public GetConnectionsArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}