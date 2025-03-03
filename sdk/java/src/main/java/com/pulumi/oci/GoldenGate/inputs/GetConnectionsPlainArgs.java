// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GoldenGate.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.GoldenGate.inputs.GetConnectionsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetConnectionsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetConnectionsPlainArgs Empty = new GetConnectionsPlainArgs();

    /**
     * Filters for compatible connections which can be, but currently not assigned to the deployment specified by its id.
     * 
     */
    @Import(name="assignableDeploymentId")
    private @Nullable String assignableDeploymentId;

    /**
     * @return Filters for compatible connections which can be, but currently not assigned to the deployment specified by its id.
     * 
     */
    public Optional<String> assignableDeploymentId() {
        return Optional.ofNullable(this.assignableDeploymentId);
    }

    /**
     * Filters for connections which can be assigned to the latest version of the specified deployment type.
     * 
     */
    @Import(name="assignableDeploymentType")
    private @Nullable String assignableDeploymentType;

    /**
     * @return Filters for connections which can be assigned to the latest version of the specified deployment type.
     * 
     */
    public Optional<String> assignableDeploymentType() {
        return Optional.ofNullable(this.assignableDeploymentType);
    }

    /**
     * The OCID of the deployment which for the connection must be assigned.
     * 
     */
    @Import(name="assignedDeploymentId")
    private @Nullable String assignedDeploymentId;

    /**
     * @return The OCID of the deployment which for the connection must be assigned.
     * 
     */
    public Optional<String> assignedDeploymentId() {
        return Optional.ofNullable(this.assignedDeploymentId);
    }

    /**
     * The OCID of the compartment that contains the work request. Work requests should be scoped  to the same compartment as the resource the work request affects. If the work request concerns  multiple resources, and those resources are not in the same compartment, it is up to the service team  to pick the primary resource whose compartment should be used.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The OCID of the compartment that contains the work request. Work requests should be scoped  to the same compartment as the resource the work request affects. If the work request concerns  multiple resources, and those resources are not in the same compartment, it is up to the service team  to pick the primary resource whose compartment should be used.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    /**
     * The array of connection types.
     * 
     */
    @Import(name="connectionTypes")
    private @Nullable List<String> connectionTypes;

    /**
     * @return The array of connection types.
     * 
     */
    public Optional<List<String>> connectionTypes() {
        return Optional.ofNullable(this.connectionTypes);
    }

    /**
     * A filter to return only the resources that match the entire &#39;displayName&#39; given.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return only the resources that match the entire &#39;displayName&#39; given.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetConnectionsFilter> filters;

    public Optional<List<GetConnectionsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only connections having the &#39;lifecycleState&#39; given.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter to return only connections having the &#39;lifecycleState&#39; given.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The array of technology types.
     * 
     */
    @Import(name="technologyTypes")
    private @Nullable List<String> technologyTypes;

    /**
     * @return The array of technology types.
     * 
     */
    public Optional<List<String>> technologyTypes() {
        return Optional.ofNullable(this.technologyTypes);
    }

    private GetConnectionsPlainArgs() {}

    private GetConnectionsPlainArgs(GetConnectionsPlainArgs $) {
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
    public static Builder builder(GetConnectionsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetConnectionsPlainArgs $;

        public Builder() {
            $ = new GetConnectionsPlainArgs();
        }

        public Builder(GetConnectionsPlainArgs defaults) {
            $ = new GetConnectionsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param assignableDeploymentId Filters for compatible connections which can be, but currently not assigned to the deployment specified by its id.
         * 
         * @return builder
         * 
         */
        public Builder assignableDeploymentId(@Nullable String assignableDeploymentId) {
            $.assignableDeploymentId = assignableDeploymentId;
            return this;
        }

        /**
         * @param assignableDeploymentType Filters for connections which can be assigned to the latest version of the specified deployment type.
         * 
         * @return builder
         * 
         */
        public Builder assignableDeploymentType(@Nullable String assignableDeploymentType) {
            $.assignableDeploymentType = assignableDeploymentType;
            return this;
        }

        /**
         * @param assignedDeploymentId The OCID of the deployment which for the connection must be assigned.
         * 
         * @return builder
         * 
         */
        public Builder assignedDeploymentId(@Nullable String assignedDeploymentId) {
            $.assignedDeploymentId = assignedDeploymentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment that contains the work request. Work requests should be scoped  to the same compartment as the resource the work request affects. If the work request concerns  multiple resources, and those resources are not in the same compartment, it is up to the service team  to pick the primary resource whose compartment should be used.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param connectionTypes The array of connection types.
         * 
         * @return builder
         * 
         */
        public Builder connectionTypes(@Nullable List<String> connectionTypes) {
            $.connectionTypes = connectionTypes;
            return this;
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
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetConnectionsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetConnectionsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param state A filter to return only connections having the &#39;lifecycleState&#39; given.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        /**
         * @param technologyTypes The array of technology types.
         * 
         * @return builder
         * 
         */
        public Builder technologyTypes(@Nullable List<String> technologyTypes) {
            $.technologyTypes = technologyTypes;
            return this;
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

        public GetConnectionsPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetConnectionsPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}
