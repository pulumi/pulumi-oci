// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataFlow.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataFlow.inputs.GetInvokeRunsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetInvokeRunsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetInvokeRunsArgs Empty = new GetInvokeRunsArgs();

    /**
     * The ID of the application.
     * 
     */
    @Import(name="applicationId")
    private @Nullable Output<String> applicationId;

    /**
     * @return The ID of the application.
     * 
     */
    public Optional<Output<String>> applicationId() {
        return Optional.ofNullable(this.applicationId);
    }

    /**
     * The OCID of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * The query parameter for the Spark application name.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return The query parameter for the Spark application name.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The displayName prefix.
     * 
     */
    @Import(name="displayNameStartsWith")
    private @Nullable Output<String> displayNameStartsWith;

    /**
     * @return The displayName prefix.
     * 
     */
    public Optional<Output<String>> displayNameStartsWith() {
        return Optional.ofNullable(this.displayNameStartsWith);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetInvokeRunsFilterArgs>> filters;

    public Optional<Output<List<GetInvokeRunsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The OCID of the user who created the resource.
     * 
     */
    @Import(name="ownerPrincipalId")
    private @Nullable Output<String> ownerPrincipalId;

    /**
     * @return The OCID of the user who created the resource.
     * 
     */
    public Optional<Output<String>> ownerPrincipalId() {
        return Optional.ofNullable(this.ownerPrincipalId);
    }

    /**
     * The ID of the pool.
     * 
     */
    @Import(name="poolId")
    private @Nullable Output<String> poolId;

    /**
     * @return The ID of the pool.
     * 
     */
    public Optional<Output<String>> poolId() {
        return Optional.ofNullable(this.poolId);
    }

    /**
     * The LifecycleState of the run.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The LifecycleState of the run.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The epoch time that the resource was created.
     * 
     */
    @Import(name="timeCreatedGreaterThan")
    private @Nullable Output<String> timeCreatedGreaterThan;

    /**
     * @return The epoch time that the resource was created.
     * 
     */
    public Optional<Output<String>> timeCreatedGreaterThan() {
        return Optional.ofNullable(this.timeCreatedGreaterThan);
    }

    private GetInvokeRunsArgs() {}

    private GetInvokeRunsArgs(GetInvokeRunsArgs $) {
        this.applicationId = $.applicationId;
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.displayNameStartsWith = $.displayNameStartsWith;
        this.filters = $.filters;
        this.ownerPrincipalId = $.ownerPrincipalId;
        this.poolId = $.poolId;
        this.state = $.state;
        this.timeCreatedGreaterThan = $.timeCreatedGreaterThan;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetInvokeRunsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetInvokeRunsArgs $;

        public Builder() {
            $ = new GetInvokeRunsArgs();
        }

        public Builder(GetInvokeRunsArgs defaults) {
            $ = new GetInvokeRunsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param applicationId The ID of the application.
         * 
         * @return builder
         * 
         */
        public Builder applicationId(@Nullable Output<String> applicationId) {
            $.applicationId = applicationId;
            return this;
        }

        /**
         * @param applicationId The ID of the application.
         * 
         * @return builder
         * 
         */
        public Builder applicationId(String applicationId) {
            return applicationId(Output.of(applicationId));
        }

        /**
         * @param compartmentId The OCID of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param displayName The query parameter for the Spark application name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName The query parameter for the Spark application name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param displayNameStartsWith The displayName prefix.
         * 
         * @return builder
         * 
         */
        public Builder displayNameStartsWith(@Nullable Output<String> displayNameStartsWith) {
            $.displayNameStartsWith = displayNameStartsWith;
            return this;
        }

        /**
         * @param displayNameStartsWith The displayName prefix.
         * 
         * @return builder
         * 
         */
        public Builder displayNameStartsWith(String displayNameStartsWith) {
            return displayNameStartsWith(Output.of(displayNameStartsWith));
        }

        public Builder filters(@Nullable Output<List<GetInvokeRunsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetInvokeRunsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetInvokeRunsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param ownerPrincipalId The OCID of the user who created the resource.
         * 
         * @return builder
         * 
         */
        public Builder ownerPrincipalId(@Nullable Output<String> ownerPrincipalId) {
            $.ownerPrincipalId = ownerPrincipalId;
            return this;
        }

        /**
         * @param ownerPrincipalId The OCID of the user who created the resource.
         * 
         * @return builder
         * 
         */
        public Builder ownerPrincipalId(String ownerPrincipalId) {
            return ownerPrincipalId(Output.of(ownerPrincipalId));
        }

        /**
         * @param poolId The ID of the pool.
         * 
         * @return builder
         * 
         */
        public Builder poolId(@Nullable Output<String> poolId) {
            $.poolId = poolId;
            return this;
        }

        /**
         * @param poolId The ID of the pool.
         * 
         * @return builder
         * 
         */
        public Builder poolId(String poolId) {
            return poolId(Output.of(poolId));
        }

        /**
         * @param state The LifecycleState of the run.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The LifecycleState of the run.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param timeCreatedGreaterThan The epoch time that the resource was created.
         * 
         * @return builder
         * 
         */
        public Builder timeCreatedGreaterThan(@Nullable Output<String> timeCreatedGreaterThan) {
            $.timeCreatedGreaterThan = timeCreatedGreaterThan;
            return this;
        }

        /**
         * @param timeCreatedGreaterThan The epoch time that the resource was created.
         * 
         * @return builder
         * 
         */
        public Builder timeCreatedGreaterThan(String timeCreatedGreaterThan) {
            return timeCreatedGreaterThan(Output.of(timeCreatedGreaterThan));
        }

        public GetInvokeRunsArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetInvokeRunsArgs", "compartmentId");
            }
            return $;
        }
    }

}
