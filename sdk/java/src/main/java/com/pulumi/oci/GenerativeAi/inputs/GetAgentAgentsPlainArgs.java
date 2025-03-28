// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GenerativeAi.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.GenerativeAi.inputs.GetAgentAgentsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetAgentAgentsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAgentAgentsPlainArgs Empty = new GetAgentAgentsPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable String compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * A filter to return only resources that match the given display name exactly.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return only resources that match the given display name exactly.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetAgentAgentsFilter> filters;

    public Optional<List<GetAgentAgentsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetAgentAgentsPlainArgs() {}

    private GetAgentAgentsPlainArgs(GetAgentAgentsPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAgentAgentsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAgentAgentsPlainArgs $;

        public Builder() {
            $ = new GetAgentAgentsPlainArgs();
        }

        public Builder(GetAgentAgentsPlainArgs defaults) {
            $ = new GetAgentAgentsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the given display name exactly.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetAgentAgentsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetAgentAgentsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param state A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetAgentAgentsPlainArgs build() {
            return $;
        }
    }

}
