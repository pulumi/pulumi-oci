// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waa.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Waa.inputs.GetAppAccelerationsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetAppAccelerationsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAppAccelerationsArgs Empty = new GetAppAccelerationsArgs();

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
     * A filter to return only resources that match the entire display name given.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetAppAccelerationsFilterArgs>> filters;

    public Optional<Output<List<GetAppAccelerationsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only the WebAppAcceleration with the given [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="id")
    private @Nullable Output<String> id;

    /**
     * @return A filter to return only the WebAppAcceleration with the given [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Optional<Output<String>> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * A filter to return only resources that match the given lifecycleState.
     * 
     */
    @Import(name="states")
    private @Nullable Output<List<String>> states;

    /**
     * @return A filter to return only resources that match the given lifecycleState.
     * 
     */
    public Optional<Output<List<String>>> states() {
        return Optional.ofNullable(this.states);
    }

    /**
     * A filter to return only the WebAppAcceleration with the given [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of related WebAppAccelerationPolicy.
     * 
     */
    @Import(name="webAppAccelerationPolicyId")
    private @Nullable Output<String> webAppAccelerationPolicyId;

    /**
     * @return A filter to return only the WebAppAcceleration with the given [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of related WebAppAccelerationPolicy.
     * 
     */
    public Optional<Output<String>> webAppAccelerationPolicyId() {
        return Optional.ofNullable(this.webAppAccelerationPolicyId);
    }

    private GetAppAccelerationsArgs() {}

    private GetAppAccelerationsArgs(GetAppAccelerationsArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.id = $.id;
        this.states = $.states;
        this.webAppAccelerationPolicyId = $.webAppAccelerationPolicyId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAppAccelerationsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAppAccelerationsArgs $;

        public Builder() {
            $ = new GetAppAccelerationsArgs();
        }

        public Builder(GetAppAccelerationsArgs defaults) {
            $ = new GetAppAccelerationsArgs(Objects.requireNonNull(defaults));
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
         * @param displayName A filter to return only resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetAppAccelerationsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetAppAccelerationsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetAppAccelerationsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param id A filter to return only the WebAppAcceleration with the given [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id A filter to return only the WebAppAcceleration with the given [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        /**
         * @param states A filter to return only resources that match the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder states(@Nullable Output<List<String>> states) {
            $.states = states;
            return this;
        }

        /**
         * @param states A filter to return only resources that match the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder states(List<String> states) {
            return states(Output.of(states));
        }

        /**
         * @param states A filter to return only resources that match the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder states(String... states) {
            return states(List.of(states));
        }

        /**
         * @param webAppAccelerationPolicyId A filter to return only the WebAppAcceleration with the given [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of related WebAppAccelerationPolicy.
         * 
         * @return builder
         * 
         */
        public Builder webAppAccelerationPolicyId(@Nullable Output<String> webAppAccelerationPolicyId) {
            $.webAppAccelerationPolicyId = webAppAccelerationPolicyId;
            return this;
        }

        /**
         * @param webAppAccelerationPolicyId A filter to return only the WebAppAcceleration with the given [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of related WebAppAccelerationPolicy.
         * 
         * @return builder
         * 
         */
        public Builder webAppAccelerationPolicyId(String webAppAccelerationPolicyId) {
            return webAppAccelerationPolicyId(Output.of(webAppAccelerationPolicyId));
        }

        public GetAppAccelerationsArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}