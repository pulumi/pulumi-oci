// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DatabaseManagement.inputs.GetExternalExadataInfrastructuresFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetExternalExadataInfrastructuresArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetExternalExadataInfrastructuresArgs Empty = new GetExternalExadataInfrastructuresArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * The optional single value query filter parameter on the entity display name.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return The optional single value query filter parameter on the entity display name.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetExternalExadataInfrastructuresFilterArgs>> filters;

    public Optional<Output<List<GetExternalExadataInfrastructuresFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetExternalExadataInfrastructuresArgs() {}

    private GetExternalExadataInfrastructuresArgs(GetExternalExadataInfrastructuresArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetExternalExadataInfrastructuresArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetExternalExadataInfrastructuresArgs $;

        public Builder() {
            $ = new GetExternalExadataInfrastructuresArgs();
        }

        public Builder(GetExternalExadataInfrastructuresArgs defaults) {
            $ = new GetExternalExadataInfrastructuresArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param displayName The optional single value query filter parameter on the entity display name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName The optional single value query filter parameter on the entity display name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetExternalExadataInfrastructuresFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetExternalExadataInfrastructuresFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetExternalExadataInfrastructuresFilterArgs... filters) {
            return filters(List.of(filters));
        }

        public GetExternalExadataInfrastructuresArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}