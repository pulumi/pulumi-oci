// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.GetInstanceConsoleConnectionsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetInstanceConsoleConnectionsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetInstanceConsoleConnectionsPlainArgs Empty = new GetInstanceConsoleConnectionsPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable List<GetInstanceConsoleConnectionsFilter> filters;

    public Optional<List<GetInstanceConsoleConnectionsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The OCID of the instance.
     * 
     */
    @Import(name="instanceId")
    private @Nullable String instanceId;

    /**
     * @return The OCID of the instance.
     * 
     */
    public Optional<String> instanceId() {
        return Optional.ofNullable(this.instanceId);
    }

    private GetInstanceConsoleConnectionsPlainArgs() {}

    private GetInstanceConsoleConnectionsPlainArgs(GetInstanceConsoleConnectionsPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.instanceId = $.instanceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetInstanceConsoleConnectionsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetInstanceConsoleConnectionsPlainArgs $;

        public Builder() {
            $ = new GetInstanceConsoleConnectionsPlainArgs();
        }

        public Builder(GetInstanceConsoleConnectionsPlainArgs defaults) {
            $ = new GetInstanceConsoleConnectionsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public Builder filters(@Nullable List<GetInstanceConsoleConnectionsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetInstanceConsoleConnectionsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param instanceId The OCID of the instance.
         * 
         * @return builder
         * 
         */
        public Builder instanceId(@Nullable String instanceId) {
            $.instanceId = instanceId;
            return this;
        }

        public GetInstanceConsoleConnectionsPlainArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}