// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DatabaseManagement.inputs.GetExternalDbNodesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetExternalDbNodesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetExternalDbNodesArgs Empty = new GetExternalDbNodesArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * A filter to only return the resources that match the entire display name.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to only return the resources that match the entire display name.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
     * 
     */
    @Import(name="externalDbSystemId")
    private @Nullable Output<String> externalDbSystemId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
     * 
     */
    public Optional<Output<String>> externalDbSystemId() {
        return Optional.ofNullable(this.externalDbSystemId);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetExternalDbNodesFilterArgs>> filters;

    public Optional<Output<List<GetExternalDbNodesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetExternalDbNodesArgs() {}

    private GetExternalDbNodesArgs(GetExternalDbNodesArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.externalDbSystemId = $.externalDbSystemId;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetExternalDbNodesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetExternalDbNodesArgs $;

        public Builder() {
            $ = new GetExternalDbNodesArgs();
        }

        public Builder(GetExternalDbNodesArgs defaults) {
            $ = new GetExternalDbNodesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
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
         * @param displayName A filter to only return the resources that match the entire display name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to only return the resources that match the entire display name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param externalDbSystemId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
         * 
         * @return builder
         * 
         */
        public Builder externalDbSystemId(@Nullable Output<String> externalDbSystemId) {
            $.externalDbSystemId = externalDbSystemId;
            return this;
        }

        /**
         * @param externalDbSystemId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
         * 
         * @return builder
         * 
         */
        public Builder externalDbSystemId(String externalDbSystemId) {
            return externalDbSystemId(Output.of(externalDbSystemId));
        }

        public Builder filters(@Nullable Output<List<GetExternalDbNodesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetExternalDbNodesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetExternalDbNodesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        public GetExternalDbNodesArgs build() {
            return $;
        }
    }

}